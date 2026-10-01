"""JEP reference API.

The current API contract targets JEP Core 0.7 under /v0.7. Historical
unversioned endpoints retain pre-0.7 compatibility behavior so existing
0.6 artifacts are not silently reinterpreted.

Current 0.7 path:
- J/D/T/V event creation with stable Event Identity (who,id)
- JEP wire version "1" with JEP-Core-0.7 profile labels
- JCS canonicalization and algorithm-tagged Event Hash
- detached JWS baseline signing and verification
- independent validation checks and structured valid/invalid/indeterminate results
- idempotent acceptance outcomes including already_accepted
- ext/ext_crit extension framework

Legacy unversioned endpoints retain explicit pre-0.7 compatibility, including
historical nonce/replay behavior. Legacy decoding is never selected by
heuristic fallback after a 0.7 failure.

This is an implementation seed, not a production security service.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import re
import hashlib
import json
import math
import time
import uuid
from copy import deepcopy
from pathlib import Path
from state import CreationConflict, configured_state
from keys import KeyManager, KeyUnavailable, InvalidPublicKey, verification_key
from nacl.signing import VerifyKey
import psycopg
import secrets
from typing import Any, Dict, List, Optional, Literal

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


JEP_CORE_PROFILE = "jep-core-0.6"  # legacy unversioned endpoint compatibility
JEP_CONFORMANCE_CLASS = "JEP-Baseline-Ed25519-JWS-JCS-0.6"
JEP_CORE_PROFILE_07 = "jep-core-0.7"
JEP_CONFORMANCE_CLASS_07 = "JEP-Baseline-Ed25519-JWS-JCS-0.7"
JEP_WIRE_VERSION = "1"

EXT_TTL = "https://jep.org/ttl"
EXT_DIGEST_ONLY = "https://jep.org/priv/digest-only"
KNOWN_EXTENSIONS = {EXT_TTL, EXT_DIGEST_ONLY}

STATE = configured_state()
KEYS = KeyManager(STATE)
VERSION = Path(__file__).with_name("VERSION").read_text().strip()
STORAGE_ERRORS = (sqlite3.Error, psycopg.Error)
if os.environ.get("JEP_DEPLOYMENT_MODE") == "production" and not os.environ.get("JEP_SIGNING_TOKEN_FILE"):
    raise ValueError("Production signing requires JEP_SIGNING_TOKEN_FILE")
MAX_AGE_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
SCHEMA = Draft202012Validator(
    json.loads(Path(__file__).with_name("jep-event.schema.json").read_text()),
    format_checker=FormatChecker(),
)
SCHEMA_07 = Draft202012Validator(
    json.loads(Path(__file__).with_name("jep-event-0.7.schema.json").read_text()),
    format_checker=FormatChecker(),
)

DEMO_KID = "did:example:jep-api#key-1"
DEMO_WHO = "did:example:jep-api"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", data) or b64u(raw) != data:
        raise ValueError("Non-canonical base64url encoding")
    return raw


def _binary64_numbers(value):
    """Adapt integer tokens to their preserved JCS binary64 value.

    JSON.stringify(1e20) emits an integer token. Parsing that token into a
    Python int must not invalidate that number. Accept an exact binary64
    integer or its canonical shortest decimal spelling, which can differ
    (1000000000000000100 represents the float 1000000000000000128).
    Other precision-losing integers remain rejected. Never edit the input.
    """
    if type(value) is int and abs(value) > 2**53 - 1:
        try:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("Integer exceeds binary64 range")
            if int(number) != value and rfc8785.dumps(number) != str(value).encode("ascii"):
                raise ValueError("Integer is neither exact binary64 nor its canonical JCS spelling")
        except OverflowError as exc:
            raise ValueError("Integer exceeds binary64 range") from exc
        return number
    if isinstance(value, dict):
        return {key: _binary64_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_binary64_numbers(item) for item in value]
    return value


def jcs_seed(obj: Any) -> bytes:
    """RFC 8785 canonicalization; rejects non-I-JSON values."""
    return rfc8785.dumps(_binary64_numbers(obj))


class DuplicateMember(ValueError):
    pass


def strict_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateMember(f"Duplicate JSON member: {key}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def event_hash(event: Dict[str, Any]) -> str:
    return sha256_digest(jcs_seed(event))


def detached_jws_sign(unsigned_event: Dict[str, Any]) -> str:
    kid, sign = KEYS.snapshot()
    protected = {
        "alg": "Ed25519",
        "kid": kid,
        "typ": "jep-event+jws",
        "jep": JEP_WIRE_VERSION,
    }
    protected_b64 = b64u(jcs_seed(protected))
    payload_b64 = b64u(jcs_seed(unsigned_event))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = sign(signing_input)
    return f"{protected_b64}..{b64u(signature)}"


def detached_jws_verify(event: Dict[str, Any], *, strict_current: bool = False) -> tuple[bool, Optional[Dict[str, Any]]]:
    sig = event.get("sig")
    if not isinstance(sig, str) or sig.count(".") != 2:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "sig is not detached JWS Compact Serialization", 1)

    protected_b64, empty, signature_b64 = sig.split(".")
    if empty != "":
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "JWS payload segment must be empty", 1)

    try:
        protected = json.loads(b64u_decode(protected_b64).decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant)
        if strict_current:
            # Validate all decoded values, but verify the original header bytes.
            # Keep explicitly selected historical parsing behavior unchanged.
            jcs_seed(protected)
    except Exception as exc:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", f"Invalid protected header: {exc}", 1)

    if not isinstance(protected, dict) or "crit" in protected or protected.get("b64", True) is not True:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "Unsupported protected header", 1)
    if not isinstance(protected.get("alg"), str) or not isinstance(protected.get("kid"), str) or not protected["kid"]:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", "Protected header requires alg and a non-empty kid", 1)
    if protected.get("alg") != "Ed25519":
        return False, error("ERR_UNSUPPORTED_SIGNATURE_ALG", f"Unsupported alg: {protected.get('alg')}", 1)

    try:
        jwk = STATE.public_keys().get(protected.get("kid"))
    except STORAGE_ERRORS:
        return False, error("ERR_KEY_UNRESOLVED", "Key registry unavailable", 1)
    if jwk is None:
        return False, error("ERR_KEY_UNRESOLVED", "Unknown signing key identifier", 1)
    try:
        raw_key = verification_key(jwk, protected["kid"])
    except InvalidPublicKey as exc:
        return False, error(exc.code, str(exc), 1)
    try:
        raw_signature = b64u_decode(signature_b64)
    except (ValueError, TypeError) as exc:
        return False, error("ERR_SIGNATURE_CONTAINER_INVALID", str(exc), 1)
    unsigned = {k: v for k, v in event.items() if k != "sig"}
    payload_b64 = b64u(jcs_seed(unsigned))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    try:
        VerifyKey(raw_key).verify(signing_input, raw_signature)
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
        "conformance_class": JEP_CONFORMANCE_CLASS,
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


class CreateEvent07Request(BaseModel):
    id: Optional[str] = Field(
        default=None, min_length=1,
        description="Caller-chosen ID. Reuse with an unchanged request to recover its original creation response (API 0.8.6+). Omit to create a new event each time.",
    )
    verb: str = Field(..., pattern="^(J|D|T|V)$")
    who: str = Field(default=DEMO_WHO, min_length=1)
    what: Any
    aud: Optional[str] = None
    ref: str | Dict[str, Any] | None = None
    ttl_minutes: Optional[int] = Field(default=None, gt=0, strict=True)
    digest_only_who: bool = False
    ext: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    ext_crit: List[str] = Field(default_factory=list)


class VerifyEvent07Request(BaseModel):
    event: Dict[str, Any]
    mode: Literal["archival", "acceptance"] = "archival"
    expected_audience: Optional[str] = None
    max_age_seconds: Optional[int] = Field(default=None, ge=0, strict=True)


class EventResponse(BaseModel):
    event: Dict[str, Any]
    event_hash: str
    validation: Dict[str, Any]


app = FastAPI(
    title="JEP Core 0.7 Reference API",
    version=VERSION,
    description="Reference API for JEP Core 0.7 with explicit pre-0.7 compatibility endpoints.",
)


@app.middleware("http")
async def reject_ambiguous_json(request: Request, call_next):
    payload = None
    if request.method == "POST" and request.url.path in {"/events/create", "/events/verify", "/events/verify-legacy", "/v0.7/events/create", "/v0.7/events/verify"}:
        try:
            payload = json.loads((await request.body()).decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant)
        except (ValueError, UnicodeError) as exc:
            if request.url.path in {"/events/verify", "/v0.7/events/verify"}:
                code = "ERR_DUPLICATE_MEMBER" if isinstance(exc, DuplicateMember) else "ERR_INVALID_JSON"
                if request.url.path == "/v0.7/events/verify":
                    checks = _checks_07()
                    checks["syntax"] = "fail"
                    result = validation_result_07(
                        "invalid", "archival", checks=checks,
                        errors=[error_07(code, str(exc), "syntax")],
                    )
                else:
                    # No event/mode can be trusted after strict JSON parsing fails.
                    result = validation_result(False, 0, "unparsed", errors=[error(code, str(exc))])
                result["detail"] = str(exc)
                return JSONResponse(status_code=400, content=result)
            return JSONResponse(status_code=400, content={"detail": str(exc)})
    mutates_state = request.url.path in {"/events/create", "/v0.7/events/create"} or (
        request.url.path in {"/events/verify", "/v0.7/events/verify"} and isinstance(payload, dict)
        and (payload.get("mode") == "acceptance" or bool(payload.get("consume_nonce")))
    )
    if request.method == "POST" and mutates_state and os.environ.get("JEP_SIGNING_TOKEN_FILE"):
        try:
            token = Path(os.environ["JEP_SIGNING_TOKEN_FILE"]).read_text().strip()
            if not token or not secrets.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
                return JSONResponse(status_code=401, content={"detail": "State-changing API authentication required"})
        except OSError:
            return JSONResponse(status_code=503, content={"detail": "API authentication unavailable"})
    return await call_next(request)


@app.get("/")
def root() -> Dict[str, Any]:
    try:
        kid, _ = KEYS.snapshot()
        current_key = STATE.public_keys()[kid]
    except (KeyUnavailable, *STORAGE_ERRORS):
        raise HTTPException(status_code=503, detail="Signing or shared state unavailable")
    return {
        "name": "JEP Core 0.7 Reference API",
        "profile": JEP_CORE_PROFILE_07,
        "wire_format": JEP_WIRE_VERSION,
        "version": VERSION,
        "revision": os.environ.get("JEP_REVISION", "development"),
        "public_key": current_key,
        "jwks_uri": "/.well-known/jwks.json",
        "endpoints": ["/health", "/v0.7/events/create", "/v0.7/events/verify"],
        "legacy_endpoints": ["/events/create", "/events/verify", "/events/verify-legacy"],
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    try:
        STATE.health()
        KEYS.snapshot()
    except (KeyUnavailable, *STORAGE_ERRORS):
        raise HTTPException(status_code=503, detail="Signing or shared state unavailable")
    return {"ok": True, "profile": JEP_CORE_PROFILE_07, "version": VERSION, "revision": os.environ.get("JEP_REVISION", "development")}


@app.get("/.well-known/jwks.json")
def jwks():
    return KEYS.jwks()


@app.get("/live")
def live():
    return {"ok": True, "version": VERSION}



def error_07(code: str, message: str, check: str, recoverable: bool = False) -> Dict[str, Any]:
    return {"code": code, "message": message, "check": check, "recoverable": recoverable}


def _safe_event_hash_07(event: Optional[Dict[str, Any]]) -> Optional[str]:
    if not event or "sig" not in event:
        return None
    try:
        return event_hash(event)
    except Exception:
        return None


def validation_result_07(
    status: str,
    mode: str,
    event: Optional[Dict[str, Any]] = None,
    *,
    checks: Optional[Dict[str, str]] = None,
    errors: Optional[List[Dict[str, Any]]] = None,
    warnings: Optional[List[Dict[str, Any]]] = None,
    acceptance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result = {
        "status": status,
        "mode": mode,
        "profile": JEP_CORE_PROFILE_07,
        "conformance_class": JEP_CONFORMANCE_CLASS_07,
        "event_identity": (
            {"who": event["who"], "id": event["id"]}
            if (isinstance(event, dict) and isinstance(event.get("who"), str) and event["who"]
                and isinstance(event.get("id"), str) and event["id"] and event["id"].isascii())
            else None
        ),
        "event_hash": _safe_event_hash_07(event),
        "checks": checks or {},
        "warnings": warnings or [],
        "errors": errors or [],
    }
    if acceptance is not None:
        result["acceptance"] = acceptance
    return result


def schema_error_code_07(event, problem):
    if problem.validator == "required":
        if isinstance(event, dict) and "sig" not in event and problem.message == "'sig' is a required property":
            return "ERR_SIGNATURE_MISSING"
        return "ERR_MISSING_REQUIRED_FIELD"
    path = list(problem.absolute_path)
    if path == ["jep"] and problem.validator == "const":
        return "ERR_UNSUPPORTED_JEP_VERSION"
    if path == ["id"]:
        return "ERR_EVENT_ID_INVALID"
    if path == ["verb"] and problem.validator == "enum":
        return "ERR_UNKNOWN_VERB"
    if path == ["when"]:
        return "ERR_INVALID_TIMESTAMP"
    if path == ["sig"]:
        return "ERR_SIGNATURE_CONTAINER_INVALID"
    pending = list(problem.context)
    while pending:
        child = pending.pop(0)
        if child.validator == "required":
            return "ERR_MISSING_REQUIRED_FIELD"
        pending.extend(child.context)
    return "ERR_INVALID_FIELD_TYPE"


def _checks_07() -> Dict[str, str]:
    return {
        "syntax": "not_checked",
        "cryptographic": "not_checked",
        "actor_binding": "not_checked",
        "freshness": "not_checked",
        "audience": "not_checked",
        "event_identity": "not_checked",
        "reference_integrity": "not_checked",
        "extension_processing": "not_checked",
        "chain_integrity": "not_checked",
        "policy": "not_checked",
    }


def validate_event_07(
    event: Dict[str, Any],
    mode: str = "archival",
    expected_audience: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    checks = _checks_07()

    def fail(code: str, message: str, check: str, *, indeterminate: bool = False):
        checks[check] = "indeterminate" if indeterminate else "fail"
        status = "indeterminate" if indeterminate else "invalid"
        acceptance = None
        if mode == "acceptance":
            acceptance = {
                "outcome": "indeterminate" if indeterminate else "rejected",
                "effect_applied": False,
            }
        return validation_result_07(
            status, mode, event,
            checks=checks,
            errors=[error_07(code, message, check)],
            acceptance=acceptance,
        )

    if mode not in {"archival", "acceptance"}:
        return fail("ERR_INVALID_MODE", "mode must be archival or acceptance", "syntax")

    try:
        jcs_seed(event)
        problem = next(SCHEMA_07.iter_errors(event), None)
    except (ValueError, TypeError) as exc:
        return fail("ERR_INVALID_JSON", str(exc), "syntax")
    if problem:
        return fail(schema_error_code_07(event, problem), problem.message, "syntax")
    if type(event.get("when")) is not int:
        return fail("ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp", "syntax")
    checks["syntax"] = "pass"

    ok, sig_error = detached_jws_verify(event, strict_current=True)
    if not ok:
        return fail(
            sig_error["code"], sig_error["message"], "cryptographic",
            indeterminate=sig_error["code"] == "ERR_KEY_UNRESOLVED",
        )
    checks["cryptographic"] = "pass"
    checks["event_identity"] = "pass"

    ext = event.get("ext", {})
    for ext_id in event.get("ext_crit", []):
        if ext_id not in ext:
            return fail("ERR_EXTENSION_SCHEMA_INVALID", f"Missing critical extension: {ext_id}", "extension_processing")
        if ext_id not in KNOWN_EXTENSIONS:
            return fail("ERR_UNKNOWN_CRITICAL_EXTENSION", f"Unsupported critical extension: {ext_id}", "extension_processing")
    ttl = ext.get(EXT_TTL)
    if ttl is not None:
        if type(ttl.get("expires_at")) is not int:
            return fail("ERR_EXTENSION_INVALID", "TTL expires_at must be integer seconds", "extension_processing")
        if "ttl_minutes" in ttl and (type(ttl["ttl_minutes"]) is not int or ttl["ttl_minutes"] <= 0):
            return fail("ERR_EXTENSION_INVALID", "TTL ttl_minutes must be a positive integer", "extension_processing")
    digest = ext.get(EXT_DIGEST_ONLY)
    if digest is not None and digest.get("who_digest") != event["who"]:
        return fail("ERR_EXTENSION_INVALID", "Digest-only who must equal who_digest", "extension_processing")
    checks["extension_processing"] = "pass"
    if mode == "acceptance" and ttl is not None:
        if int(time.time()) >= ttl["expires_at"]:
            return fail("ERR_EVENT_EXPIRED", "Event TTL expired", "freshness")
        checks["freshness"] = "pass"

    if "ref" not in event:
        checks["reference_integrity"] = "not_applicable"

    if expected_audience is not None:
        if event.get("aud") != expected_audience:
            return fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "Audience mismatch", "audience")
        checks["audience"] = "pass"

    if max_age_seconds is not None:
        now = int(time.time())
        if event["when"] < now - max_age_seconds:
            return fail("ERR_EVENT_EXPIRED", "Event is older than the requested freshness window", "freshness")
        if event["when"] > now + CLOCK_SKEW_SECONDS:
            return fail("ERR_TIMESTAMP_OUT_OF_WINDOW", "Event timestamp is too far in the future", "freshness")
        checks["freshness"] = "pass"

    if mode == "archival":
        return validation_result_07("valid", mode, event, checks=checks)

    unsigned = {k: v for k, v in event.items() if k != "sig"}
    payload_digest = sha256_digest(jcs_seed(unsigned))
    try:
        outcome = STATE.accept_event_identity(
            event["who"], event["id"], payload_digest, event_hash(event), now=int(time.time())
        )
    except STORAGE_ERRORS:
        return fail(
            "ERR_ACCEPTANCE_STATE_UNAVAILABLE",
            "Acceptance state is unavailable",
            "event_identity",
            indeterminate=True,
        )

    if outcome == "conflict":
        return fail("ERR_EVENT_ID_CONFLICT", "Event Identity was already bound to different unsigned content", "event_identity")
    if outcome == "already_accepted":
        return validation_result_07(
            "valid", mode, event, checks=checks,
            acceptance={"outcome": "already_accepted", "effect_applied": False},
        )
    return validation_result_07(
        "valid", mode, event, checks=checks,
        acceptance={"outcome": "accepted", "effect_applied": True},
    )


@app.post("/v0.7/events/create", response_model=EventResponse)
def create_event_07(req: CreateEvent07Request) -> Dict[str, Any]:
    request_key = request_digest = None
    if req.id is not None:
        try:
            # Hash the caller identity rather than storing plaintext who in the
            # retry ledger, including when digest_only_who is requested.
            request_key = sha256_digest(jcs_seed({"who": req.who, "id": req.id}))
            request_digest = sha256_digest(jcs_seed(req.model_dump()))
            previous = STATE.created_response(request_key, request_digest)
            if previous is not None:
                return previous
        except CreationConflict as exc:
            raise HTTPException(status_code=409, detail={"code": "ERR_CREATE_REQUEST_CONFLICT", "message": str(exc)}) from exc
        except STORAGE_ERRORS as exc:
            raise HTTPException(status_code=503, detail="Creation state is unavailable") from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
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
        "id": req.id or f"urn:uuid:{uuid.uuid4()}",
        "verb": req.verb,
        "who": who,
        "when": now,
        "what": req.what,
    }
    if req.aud is not None:
        event["aud"] = req.aud
    if req.ref is not None:
        event["ref"] = req.ref
    if ext:
        event["ext"] = ext
    if ext_crit:
        event["ext_crit"] = ext_crit

    try:
        event["sig"] = detached_jws_sign(event)
    except KeyUnavailable as exc:
        raise HTTPException(status_code=503, detail="Signing provider unavailable") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = validate_event_07(event, mode="archival")
    if result["status"] != "valid":
        raise HTTPException(status_code=422, detail=result)
    h = event_hash(event)
    response = {"event": event, "event_hash": h, "validation": result}
    try:
        if request_key is not None:
            return STATE.save_created_response(request_key, request_digest, response)
        STATE.save_event(h, event)
    except CreationConflict as exc:
        raise HTTPException(status_code=409, detail={"code": "ERR_CREATE_REQUEST_CONFLICT", "message": str(exc)}) from exc
    except STORAGE_ERRORS as exc:
        raise HTTPException(status_code=503, detail="Event storage is unavailable") from exc
    return response


@app.post("/v0.7/events/verify")
def verify_event_07(req: VerifyEvent07Request) -> Dict[str, Any]:
    return validate_event_07(
        req.event,
        mode=req.mode,
        expected_audience=req.expected_audience,
        max_age_seconds=req.max_age_seconds,
    )


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
    except KeyUnavailable as exc:
        raise HTTPException(status_code=503, detail="Signing provider unavailable") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    h = event_hash(event)
    result = validate_event(event, mode="archival", consume_nonce=False)
    if not result["valid"]:
        raise HTTPException(status_code=422, detail=result)
    try:
        STATE.save_event(h, event)
    except STORAGE_ERRORS as exc:
        raise HTTPException(status_code=503, detail="Event storage is unavailable") from exc
    return {"event": event, "event_hash": h, "validation": result}


@app.post("/events/verify")
def verify_event(req: VerifyEventRequest) -> Dict[str, Any]:
    return validate_event(req.event, mode=req.mode, consume_nonce=req.consume_nonce, expected_audience=req.expected_audience)


def schema_error_code(event, problem):
    """Map schema failures to the core 0.6 diagnostic vocabulary.

    The event schema remains the structural authority. Verb-specific required
    fields are nested inside oneOf, so inspect its object-branch diagnostics.
    """
    if problem.validator == "required":
        if isinstance(event, dict) and "sig" not in event and problem.message == "'sig' is a required property":
            return "ERR_SIGNATURE_MISSING"
        return "ERR_MISSING_REQUIRED_FIELD"
    path = list(problem.absolute_path)
    if path == ["jep"] and problem.validator == "const":
        return "ERR_UNSUPPORTED_JEP_VERSION"
    if path == ["verb"] and problem.validator == "enum":
        return "ERR_UNKNOWN_VERB"
    if path == ["when"]:
        return "ERR_INVALID_TIMESTAMP"
    if path == ["sig"]:
        return "ERR_SIGNATURE_CONTAINER_INVALID"
    if path in [["what"], ["ref"]] and problem.instance is None:
        return "ERR_MISSING_REQUIRED_FIELD"
    pending = list(problem.context)
    while pending:
        child = pending.pop(0)
        if child.validator == "required" and isinstance(child.instance, dict) and child.instance:
            return "ERR_MISSING_REQUIRED_FIELD"
        pending.extend(child.context)
    return "ERR_INVALID_FIELD_TYPE"


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
        code = schema_error_code(event, problem)
        return fail(code, problem.message)
    if type(event.get("when")) is not int:
        return fail("ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp")

    ok, sig_error = detached_jws_verify(event)
    if not ok:
        return validation_result(False, 0, mode, errors=[sig_error], scopes=["syntax"])
    scopes = ["syntax", "cryptographic"]
    ext = event.get("ext", {})
    for ext_id in event.get("ext_crit", []):
        if ext_id not in ext:
            return fail("ERR_EXTENSION_SCHEMA_INVALID", f"Missing critical extension: {ext_id}", 1, scopes)
        if ext_id not in KNOWN_EXTENSIONS:
            return fail("ERR_UNKNOWN_CRITICAL_EXTENSION", f"Unsupported critical extension: {ext_id}", 1, scopes)

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
        try:
            consumed = STATE.consume_nonce(event["who"], event.get("aud", ""), event["nonce"],
                now=now, expires=max(now, event["when"]) + MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS)
        except STORAGE_ERRORS:
            return fail("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "Replay storage is unavailable", 1, scopes)
        if not consumed:
            return fail("ERR_NONCE_REPLAY", "Nonce already consumed in this actor/audience domain", 1, scopes)

    warnings = []
    if mode == "archival":
        warnings.append(error("ACCEPTANCE_NOT_CHECKED", "Historical integrity only; freshness and live authorization were not checked.", 1))
    return validation_result(True, 1, mode, event=event, scopes=scopes, warnings=warnings)


class LegacyVerifyRequest(BaseModel):
    event: Dict[str, Any]
    format: Literal["json-sorted-v1", "hf-space-v06"]


@app.post("/events/verify-legacy")
def verify_legacy(req: LegacyVerifyRequest):
    from compatibility import verify_legacy_event
    return verify_legacy_event(req.event, req.format, STATE.public_keys())
