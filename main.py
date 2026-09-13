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
import re
import hashlib
import json
import time
import uuid
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Literal

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


JEP_CORE_PROFILE = "jep-core-0.6"
JEP_WIRE_VERSION = "1"

EXT_TTL = "https://jep.org/ttl"
EXT_DIGEST_ONLY = "https://jep.org/priv/digest-only"
KNOWN_EXTENSIONS = {EXT_TTL, EXT_DIGEST_ONLY}

# Demo in-memory stores.
EVENT_STORE: Dict[str, Dict[str, Any]] = {}
CONSUMED_NONCES: Dict[tuple[str, str, str], int] = {}
NONCE_LOCK = Lock()
MAX_AGE_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
SCHEMA = Draft202012Validator(
    json.loads(Path(__file__).with_name("jep-event.schema.json").read_text()),
    format_checker=FormatChecker(),
)

# Demo process-local signing key. Production deployments must use a managed key.
SIGNING_KEY = Ed25519PrivateKey.generate()
VERIFY_KEY = SIGNING_KEY.public_key()
DEMO_KID = "did:example:jep-api#key-1"
DEMO_WHO = "did:example:jep-api"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", data) or b64u(raw) != data:
        raise ValueError("Non-canonical base64url encoding")
    return raw


def jcs_seed(obj: Any) -> bytes:
    """RFC 8785 canonicalization; rejects non-I-JSON values."""
    return rfc8785.dumps(obj)


def strict_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"Duplicate JSON member: {key}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


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
        protected = json.loads(b64u_decode(protected_b64), object_pairs_hook=strict_object, parse_constant=reject_constant)
    except Exception as exc:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", f"Invalid protected header: {exc}", 1)

    if not isinstance(protected, dict) or "crit" in protected or protected.get("b64", True) is not True:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "Unsupported protected header", 1)
    if protected.get("alg") != "Ed25519":
        return False, error("ERR_UNSUPPORTED_SIGNATURE_ALG", f"Unsupported alg: {protected.get('alg')}", 1)

    if protected.get("kid") != DEMO_KID:
        return False, error("ERR_KEY_UNRESOLVED", "Unknown signing key identifier", 1)
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
    who: str = Field(default=DEMO_WHO, min_length=1)
    what: Any
    aud: Optional[str] = "https://api.example.org"
    ref: str | Dict[str, Any] | None = None
    ttl_minutes: Optional[int] = Field(default=None, gt=0, strict=True)
    digest_only_who: bool = False
    ext: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    ext_crit: List[str] = Field(default_factory=list)


class VerifyEventRequest(BaseModel):
    event: Dict[str, Any]
    mode: Literal["archival", "acceptance"] = "archival"
    consume_nonce: bool = False
    expected_audience: Optional[str] = None


class EventResponse(BaseModel):
    event: Dict[str, Any]
    event_hash: str
    validation: Dict[str, Any]


app = FastAPI(
    title="JEP v0.6 API Seed",
    version="0.6.0",
    description="FastAPI seed for JEP v0.6 event creation and verification.",
)


@app.middleware("http")
async def reject_ambiguous_json(request: Request, call_next):
    if request.method == "POST" and request.url.path in {"/events/create", "/events/verify"}:
        try:
            json.loads(await request.body(), object_pairs_hook=strict_object, parse_constant=reject_constant)
        except (ValueError, UnicodeError) as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})
    return await call_next(request)


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
    ext = deepcopy(req.ext or {})
    ext_crit = list(req.ext_crit or [])

    if req.digest_only_who:
        salt = b64u(hashlib.sha256(str(uuid.uuid4()).encode()).digest()[:16])
        who_digest = sha256_digest(f"{who}:{salt}".encode("utf-8"))
        who = who_digest
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
    if req.aud is None:
        event.pop("aud")

    if ext:
        event["ext"] = ext
    if ext_crit:
        event["ext_crit"] = ext_crit

    try:
        event["sig"] = detached_jws_sign(event)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    h = event_hash(event)
    result = validate_event(event, mode="archival", consume_nonce=False)
    if not result["valid"]:
        raise HTTPException(status_code=422, detail=result)
    EVENT_STORE[h] = deepcopy(event)
    return {"event": event, "event_hash": h, "validation": result}


@app.post("/events/verify")
def verify_event(req: VerifyEventRequest) -> Dict[str, Any]:
    return validate_event(req.event, mode=req.mode, consume_nonce=req.consume_nonce, expected_audience=req.expected_audience)


def validate_event(event: Dict[str, Any], mode: str = "archival", consume_nonce: bool = False,
                   expected_audience: Optional[str] = None) -> Dict[str, Any]:
    def fail(code, message, level=0, scopes=None):
        return validation_result(False, level, mode, errors=[error(code, message, level)], scopes=scopes)

    if mode not in {"archival", "acceptance"}:
        return fail("ERR_INVALID_MODE", "mode must be archival or acceptance")
    try:
        jcs_seed(event)
        problem = next(SCHEMA.iter_errors(event), None)
    except (ValueError, TypeError) as exc:
        return fail("ERR_INVALID_JSON", str(exc))
    if problem:
        return fail("ERR_SCHEMA_INVALID", problem.message)

    ok, sig_error = detached_jws_verify(event)
    if not ok:
        return validation_result(False, 0, mode, errors=[sig_error], scopes=["syntax"])
    scopes = ["syntax", "cryptographic"]
    ext = event.get("ext", {})
    for ext_id in event.get("ext_crit", []):
        if ext_id not in KNOWN_EXTENSIONS:
            return fail("ERR_UNKNOWN_CRITICAL_EXTENSION", f"Unsupported critical extension: {ext_id}", 1, scopes)
        if ext_id not in ext:
            return fail("ERR_CRITICAL_EXTENSION_MISSING", f"Missing critical extension: {ext_id}", 1, scopes)

    ttl = ext.get(EXT_TTL)
    if ttl is not None:
        if type(ttl.get("expires_at")) is not int:
            return fail("ERR_EXTENSION_INVALID", "TTL expires_at must be integer seconds", 1, scopes)
        if "ttl_minutes" in ttl and (type(ttl["ttl_minutes"]) is not int or ttl["ttl_minutes"] <= 0):
            return fail("ERR_EXTENSION_INVALID", "TTL ttl_minutes must be a positive integer", 1, scopes)
    digest = ext.get(EXT_DIGEST_ONLY)
    if digest is not None and digest.get("who_digest") != event["who"]:
        return fail("ERR_EXTENSION_INVALID", "Digest-only who must equal who_digest", 1, scopes)

    now = int(time.time())
    if mode == "acceptance":
        if not expected_audience:
            return fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "Acceptance requires expected_audience", 1, scopes)
        if event.get("aud") != expected_audience:
            return fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "Audience mismatch", 1, scopes)
        if event["when"] < now - MAX_AGE_SECONDS or event["when"] > now + CLOCK_SKEW_SECONDS:
            return fail("ERR_INVALID_TIMESTAMP", "Event is outside the acceptance window", 1, scopes)
        if ttl is not None and now >= ttl["expires_at"]:
            return fail("ERR_POLICY_REJECTED", "Event TTL expired", 1, scopes)

    # Consume only after all checks pass, atomically and in the actor/audience domain.
    # Acceptance always consumes; archival only does so when explicitly requested.
    if mode == "acceptance" or consume_nonce:
        nonce_key = (event["who"], event.get("aud", ""), event["nonce"])
        with NONCE_LOCK:
            for key, expires in list(CONSUMED_NONCES.items()):
                if expires < now:
                    del CONSUMED_NONCES[key]
            if nonce_key in CONSUMED_NONCES:
                return fail("ERR_NONCE_REPLAY", "Nonce already consumed in this actor/audience domain", 1, scopes)
            CONSUMED_NONCES[nonce_key] = max(now, event["when"]) + MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS

    warnings = []
    if mode == "archival":
        warnings.append({"code": "ACCEPTANCE_NOT_CHECKED", "message": "Historical integrity only; freshness and live authorization were not checked."})
    return validation_result(True, 1, mode, event=event, scopes=scopes, warnings=warnings)
