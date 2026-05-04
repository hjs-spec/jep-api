"""JEP v0.6 API seed.

This FastAPI service is a small reference API seed for JEP v0.6-style
event creation and verification.

Implemented:
- J/D/T/V event creation
- JEP wire version "1"
- JEP-Core-0.6 profile labels
- JCS-compatible seed canonicalization
- algorithm-tagged event hash
- detached JWS Compact Serialization shape
- Ed25519 signing and verification
- ext/ext_crit extension framework
- TTL and digest-only privacy extensions
- JEP-style validation result object
- replay cache separation for verification consumption

This is an implementation seed, not a production security service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


JEP_CORE_PROFILE = "jep-core-0.6"
JEP_WIRE_VERSION = "1"

EXT_TTL = "https://jep.org/ttl"
EXT_DIGEST_ONLY = "https://jep.org/priv/digest-only"
KNOWN_EXTENSIONS = {EXT_TTL, EXT_DIGEST_ONLY}

# Demo in-memory stores.
EVENT_STORE: Dict[str, Dict[str, Any]] = {}
CONSUMED_NONCES: set[str] = set()

# Demo process-local signing key. Production deployments must use a managed key.
SIGNING_KEY = Ed25519PrivateKey.generate()
VERIFY_KEY = SIGNING_KEY.public_key()
DEMO_KID = "did:example:jep-api#key-1"
DEMO_WHO = "did:example:jep-api"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def jcs_seed(obj: Any) -> bytes:
    """JCS-compatible canonicalization for seed objects.

    This is sufficient for deterministic seed vectors. Production
    implementations should use a complete RFC 8785 JCS implementation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def event_hash(event: Dict[str, Any]) -> str:
    return sha256_digest(jcs_seed(event))


def detached_jws_sign(unsigned_event: Dict[str, Any]) -> str:
    protected = {
        "alg": "Ed25519",
        "kid": DEMO_KID,
        "typ": "jep-event+jws",
        "jep": JEP_WIRE_VERSION,
    }
    protected_b64 = b64u(jcs_seed(protected))
    payload_b64 = b64u(jcs_seed(unsigned_event))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = SIGNING_KEY.sign(signing_input)
    return f"{protected_b64}..{b64u(signature)}"


def detached_jws_verify(event: Dict[str, Any]) -> tuple[bool, Optional[Dict[str, Any]]]:
    sig = event.get("sig")
    if not isinstance(sig, str) or sig.count(".") != 2:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "sig is not detached JWS Compact Serialization", 1)

    protected_b64, empty, signature_b64 = sig.split(".")
    if empty != "":
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "JWS payload segment must be empty", 1)

    try:
        protected = json.loads(b64u_decode(protected_b64))
    except Exception as exc:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", f"Invalid protected header: {exc}", 1)

    if protected.get("alg") != "Ed25519":
        return False, error("ERR_UNSUPPORTED_SIGNATURE_ALG", f"Unsupported alg: {protected.get('alg')}", 1)

    unsigned = {k: v for k, v in event.items() if k != "sig"}
    payload_b64 = b64u(jcs_seed(unsigned))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    try:
        VERIFY_KEY.verify(b64u_decode(signature_b64), signing_input)
        return True, None
    except Exception as exc:
        return False, error("ERR_SIGNATURE_INVALID", str(exc), 1)


def error(code: str, message: str, level: int = 0, recoverable: bool = False) -> Dict[str, Any]:
    return {"code": code, "message": message, "level": level, "recoverable": recoverable}


def validation_result(
    valid: bool,
    level: int,
    mode: str,
    event: Optional[Dict[str, Any]] = None,
    errors: Optional[List[Dict[str, Any]]] = None,
    warnings: Optional[List[Dict[str, Any]]] = None,
    scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "valid": valid,
        "level": level,
        "mode": mode,
        "profile": JEP_CORE_PROFILE,
        "scopes": scopes or [],
        "event_hash": event_hash(event) if event else None,
        "warnings": warnings or [],
        "errors": errors or [],
    }


class CreateEventRequest(BaseModel):
    verb: str = Field(..., pattern="^(J|D|T|V)$")
    who: str = Field(default=DEMO_WHO)
    what: Any
    aud: Optional[str] = "https://api.example.org"
    ref: Optional[str] = None
    ttl_minutes: Optional[int] = None
    digest_only_who: bool = False
    ext: Dict[str, Any] = Field(default_factory=dict)
    ext_crit: List[str] = Field(default_factory=list)


class VerifyEventRequest(BaseModel):
    event: Dict[str, Any]
    mode: str = "archival"
    consume_nonce: bool = False


class EventResponse(BaseModel):
    event: Dict[str, Any]
    event_hash: str
    validation: Dict[str, Any]


app = FastAPI(
    title="JEP v0.6 API Seed",
    version="0.6.0",
    description="FastAPI seed for JEP v0.6 event creation and verification.",
)


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "name": "JEP v0.6 API Seed",
        "profile": JEP_CORE_PROFILE,
        "wire_format": JEP_WIRE_VERSION,
        "public_key": {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": DEMO_KID,
            "x": b64u(VERIFY_KEY.public_bytes_raw()),
        },
        "endpoints": ["/health", "/events/create", "/events/verify"],
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "profile": JEP_CORE_PROFILE}


@app.post("/events/create", response_model=EventResponse)
def create_event(req: CreateEventRequest) -> Dict[str, Any]:
    now = int(time.time())

    who = req.who
    ext = dict(req.ext or {})
    ext_crit = list(req.ext_crit or [])

    if req.digest_only_who:
        salt = b64u(hashlib.sha256(str(uuid.uuid4()).encode()).digest()[:16])
        who_digest = sha256_digest(f"{who}:{salt}".encode("utf-8"))
        ext.setdefault(EXT_DIGEST_ONLY, {})["who_digest"] = who_digest
        ext[EXT_DIGEST_ONLY]["salt_hint"] = "not disclosed"
        if EXT_DIGEST_ONLY not in ext_crit:
            ext_crit.append(EXT_DIGEST_ONLY)

    if req.ttl_minutes is not None:
        ext.setdefault(EXT_TTL, {})["ttl_minutes"] = req.ttl_minutes
        ext[EXT_TTL]["expires_at"] = now + req.ttl_minutes * 60
        if EXT_TTL not in ext_crit:
            ext_crit.append(EXT_TTL)

    event = {
        "jep": JEP_WIRE_VERSION,
        "verb": req.verb,
        "who": who,
        "when": now,
        "what": req.what,
        "nonce": str(uuid.uuid4()),
        "aud": req.aud,
        "ref": req.ref,
    }

    if ext:
        event["ext"] = ext
    if ext_crit:
        event["ext_crit"] = ext_crit

    event["sig"] = detached_jws_sign(event)

    h = event_hash(event)
    EVENT_STORE[h] = event

    result = validate_event(event, mode="archival", consume_nonce=False)
    return {"event": event, "event_hash": h, "validation": result}


@app.post("/events/verify")
def verify_event(req: VerifyEventRequest) -> Dict[str, Any]:
    return validate_event(req.event, mode=req.mode, consume_nonce=req.consume_nonce)


def validate_event(event: Dict[str, Any], mode: str = "archival", consume_nonce: bool = False) -> Dict[str, Any]:
    required = ["jep", "verb", "who", "when", "nonce", "sig"]
    for field in required:
        if field not in event:
            return validation_result(False, 0, mode, errors=[
                error("ERR_MISSING_REQUIRED_FIELD", f"Missing {field}", 0)
            ])

    if event.get("jep") != JEP_WIRE_VERSION:
        return validation_result(False, 0, mode, event=event, errors=[
            error("ERR_UNSUPPORTED_JEP_VERSION", "jep must be '1'", 0)
        ])

    if event.get("verb") not in {"J", "D", "T", "V"}:
        return validation_result(False, 0, mode, event=event, errors=[
            error("ERR_UNKNOWN_VERB", "verb must be J/D/T/V", 0)
        ])

    if not isinstance(event.get("when"), int):
        return validation_result(False, 0, mode, event=event, errors=[
            error("ERR_INVALID_TIMESTAMP", "when must be integer seconds", 0)
        ])

    if event.get("verb") in {"J", "D", "T"} and "what" not in event:
        return validation_result(False, 0, mode, event=event, errors=[
            error("ERR_MISSING_REQUIRED_FIELD", f"{event.get('verb')} requires what", 0)
        ])

    if event.get("verb") == "V" and (not event.get("ref")):
        return validation_result(False, 0, mode, event=event, errors=[
            error("ERR_MISSING_REQUIRED_FIELD", "V requires ref", 0)
        ])

    if consume_nonce:
        nonce = event.get("nonce")
        if nonce in CONSUMED_NONCES:
            return validation_result(False, 1, mode, event=event, errors=[
                error("ERR_NONCE_REPLAY", "nonce already consumed", 2)
            ], scopes=["syntax"])
        CONSUMED_NONCES.add(nonce)

    ok, sig_error = detached_jws_verify(event)
    if not ok:
        return validation_result(False, 0, mode, event=event, errors=[sig_error], scopes=["syntax"])

    warnings: List[Dict[str, Any]] = []
    for ext_id in event.get("ext_crit", []) or []:
        if ext_id not in KNOWN_EXTENSIONS and not ext_id.startswith("https://jac.org/") and not ext_id.startswith("https://hjs.org/"):
            return validation_result(False, 2, mode, event=event, errors=[
                error("ERR_UNKNOWN_CRITICAL_EXTENSION", f"Unknown critical extension: {ext_id}", 3)
            ], scopes=["syntax", "cryptographic"])

    ext = event.get("ext", {})
    ttl = ext.get(EXT_TTL, {})
    if isinstance(ttl, dict) and ttl.get("expires_at") and int(time.time()) > int(ttl["expires_at"]):
        return validation_result(False, 3, mode, event=event, errors=[
            error("ERR_POLICY_REJECTED", "event TTL expired", 4)
        ], scopes=["syntax", "cryptographic", "extension_processing"])

    return validation_result(
        True,
        1,
        mode,
        event=event,
        warnings=warnings,
        scopes=["syntax", "cryptographic"],
    )
