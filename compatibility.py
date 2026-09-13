"""Historical integrity only. No automatic fallback, acceptance, migration or re-signing."""
import json
import hashlib
from keys import decode, b64, unique
from nacl.signing import VerifyKey

def verify_legacy_event(event, format, keys):
    result={"valid":False,"mode":"archival","profile":"legacy-"+format,"level":0,"scopes":[],"event_hash":None,"errors":[],"warnings":[{"code":"LEGACY_FORMAT","message":"Historical signature integrity only; current JEP conformance, freshness and authorization are not asserted."}]}
    try:
        if format not in {"json-sorted-v1","hf-space-v06"}:
            raise ValueError("Unsupported legacy format")
        if not isinstance(event,dict) or not isinstance(event.get("who"),str) or not event["who"]:
            raise ValueError("Missing historical actor")
        # HF created events omitted null members. Reject later unsigned null insertion.
        if format=="hf-space-v06" and any(v is None for v in event.values()):
            raise ValueError("HF historical events must not contain unsigned null members")
        protected,empty,signature=event["sig"].split(".")
        if empty:
            raise ValueError("Expected detached JWS")
        header=json.loads(decode(protected).decode("utf-8"),object_pairs_hook=unique)
        if header.get("alg")!="Ed25519" or "crit" in header or header.get("b64",True) is not True:
            raise ValueError("Unsupported historical signature header")
        key=keys.get(header.get("kid"))
        if key is None:
            result["errors"]=[{"code":"ERR_KEY_UNRESOLVED","message":"Historical trusted public key is unavailable"}]
            return result
        if key.get("kty")!="OKP" or key.get("crv")!="Ed25519":
            raise ValueError("Expected trusted Ed25519 key")
        unsigned={k:v for k,v in event.items() if k!="sig"}
        def canonical(v):
            return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
        VerifyKey(decode(key["x"])).verify((protected+"."+b64(canonical(unsigned))).encode("ascii"),decode(signature))
        result.update(valid=True,scopes=["legacy_signature_integrity"],event_hash="sha256:"+hashlib.sha256(canonical(event)).hexdigest())
    except Exception:
        result["errors"]=[{"code":"ERR_LEGACY_SIGNATURE_INVALID","message":"Invalid historical event or signature"}]
    return result
