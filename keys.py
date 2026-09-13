"""Explicit Ed25519 key sources, rotation, and immutable public key history."""
from __future__ import annotations
import base64
import json
import os
import re
from pathlib import Path
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.signing import VerifyKey

class KeyUnavailable(RuntimeError):
    pass

class InvalidPublicKey(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

def verification_key(key, kid):
    """Validate resolved key metadata before using any public key bytes."""
    if not isinstance(key, dict) or key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise InvalidPublicKey("ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 requires an OKP/Ed25519 JWK")
    if "kid" in key and key["kid"] != kid:
        raise InvalidPublicKey("ERR_KEY_UNRESOLVED", "Resolved JWK kid does not match the requested key")
    if "alg" in key and key["alg"] != "Ed25519":
        raise InvalidPublicKey("ERR_ALG_PROFILE_MISMATCH", "JWK alg does not match Ed25519")
    if "use" in key and key["use"] != "sig":
        raise InvalidPublicKey("ERR_PROHIBITED_SIGNATURE_ALG", "JWK use does not permit signatures")
    if "key_ops" in key:
        ops = key["key_ops"]
        if not isinstance(ops, list) or not all(isinstance(op, str) for op in ops) or len(ops) != len(set(ops)) or "verify" not in ops:
            raise InvalidPublicKey("ERR_PROHIBITED_SIGNATURE_ALG", "JWK key_ops does not permit verification")
    try:
        raw = decode(key["x"])
        if len(raw) != 32:
            raise ValueError("Invalid key length")
    except (KeyError, TypeError, ValueError):
        raise InvalidPublicKey("ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 requires a canonical 32-byte public key") from None
    return raw

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def decode(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(raw) != value:
        raise ValueError("Non-canonical key encoding")
    return raw

def unique(pairs):
    out = {}
    for k,v in pairs:
        if k in out:
            raise ValueError("Duplicate key configuration member")
        out[k] = v
    return out

def public(kid, raw):
    return {"kid":kid,"kty":"OKP","crv":"Ed25519","x":b64(raw)}

class KeyManager:
    def __init__(self, state):
        self.state = state
        self.file = os.environ.get("JEP_KEYRING_FILE")
        self.vault = os.environ.get("JEP_VAULT_ADDR")
        if self.file and self.vault:
            raise ValueError("Select one signing key provider")
        self.local = None
        if not self.file and not self.vault:
            if not hasattr(state,"signing_key") or os.environ.get("JEP_DEPLOYMENT_MODE") == "production":
                raise ValueError("Shared/production API requires an external signing key provider")
            self.local = state.signing_key()
        self.snapshot()

    def snapshot(self):
        """Read a complete configuration per signing operation; never mix rotation versions."""
        try:
            if self.local is not None:
                kid = "did:example:jep-api#key-1"
                jwk = public(kid,self.local.public_key().public_bytes_raw())
                self.state.register_public_key(kid,jwk)
                return kid,self.local.sign
            if self.file:
                path = Path(self.file)
                if path.stat().st_mode & 0o077:
                    raise ValueError("Private keyring permissions must be 0600 or 0400")
                data = json.loads(path.read_text(),object_pairs_hook=unique)
                active = data["active_kid"]
                private = None
                seen = set()
                for key in data["keys"]:
                    kid=key["kid"]
                    if not isinstance(kid,str) or not kid or kid in seen or key.get("kty")!="OKP" or key.get("crv")!="Ed25519":
                        raise ValueError("Invalid or duplicate Ed25519 key")
                    seen.add(kid)
                    raw=verification_key(key,kid)
                    jwk=public(kid,raw)
                    if "d" in key:
                        signing=Ed25519PrivateKey.from_private_bytes(decode(key["d"]))
                        if signing.public_key().public_bytes_raw()!=raw:
                            raise ValueError("Private/public key mismatch")
                        if kid==active:
                            if "key_ops" in key and "sign" not in key["key_ops"]:
                                raise ValueError("Active key does not permit signing")
                            private=signing
                    self.state.register_public_key(kid,jwk)
                if private is None:
                    raise ValueError("Active key requires private material")
                return active,private.sign
            addr=self.vault.rstrip("/")
            if not addr.startswith("https://") and not (os.environ.get("JEP_VAULT_ALLOW_HTTP")=="1" and os.environ.get("JEP_DEPLOYMENT_MODE")!="production"):
                raise ValueError("Vault requires HTTPS")
            token=Path(os.environ["JEP_VAULT_TOKEN_FILE"]).read_text().strip()
            name=os.environ["JEP_VAULT_KEY"]
            mount=os.environ.get("JEP_VAULT_MOUNT","transit")
            if not re.fullmatch(r"[A-Za-z0-9_-]+",name) or not re.fullmatch(r"[A-Za-z0-9_/-]+",mount) or ".." in mount:
                raise ValueError("Invalid Vault key path")
            headers={"X-Vault-Token":token}
            if os.environ.get("JEP_VAULT_NAMESPACE"):
                headers["X-Vault-Namespace"]=os.environ["JEP_VAULT_NAMESPACE"]
            ca=os.environ.get("JEP_VAULT_CACERT")
            import ssl
            verify=ssl.create_default_context(cafile=ca) if ca else True
            with httpx.Client(timeout=10,verify=verify,follow_redirects=False) as client:
                response=client.get(f"{addr}/v1/{mount}/keys/{name}",headers=headers)
                response.raise_for_status();data=response.json()["data"]
            if data["type"]!="ed25519" or data.get("derived"):
                raise ValueError("Vault key must be non-derived Ed25519")
            version=data["latest_version"]
            prefix=os.environ["JEP_VAULT_KID_PREFIX"]
            for v,key in data["keys"].items():
                raw=base64.b64decode(key["public_key"],validate=True)
                if len(raw)!=32:
                    raise ValueError("Invalid Vault public key")
                kid=f"{prefix}:v{v}"
                self.state.register_public_key(kid,public(kid,raw))
            kid=f"{prefix}:v{version}"
            def sign(payload):
                try:
                    with httpx.Client(timeout=10,verify=verify,follow_redirects=False) as client:
                        r=client.post(f"{addr}/v1/{mount}/sign/{name}",headers=headers,json={"input":base64.b64encode(payload).decode(),"key_version":version,"prehashed":False})
                        r.raise_for_status();signature=r.json()["data"]["signature"]
                    label,actual,encoded=signature.split(":")
                    if label!="vault" or actual!=f"v{version}":
                        raise ValueError("Vault signing version mismatch")
                    signature=base64.b64decode(encoded,validate=True)
                    VerifyKey(decode(self.state.public_keys()[kid]["x"])).verify(payload,signature)
                    return signature
                except Exception as exc:
                    raise KeyUnavailable("Signing provider unavailable") from exc
            return kid,sign
        except Exception as exc:
            raise KeyUnavailable("Signing key configuration unavailable") from exc

    def jwks(self):
        return {"keys":list(self.state.public_keys().values())}
