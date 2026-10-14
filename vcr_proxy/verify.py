import base64
import binascii
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import unquote, urlsplit

from .redact import REDACTION_MARKER, exposed_query_keys, redact_body, redact_url


REQUIRED_REQUEST_KEYS = {"method", "url", "headers", "body_b64", "body_sha256", "truncated"}
REQUIRED_RESPONSE_KEYS = {"status", "reason", "headers", "body_b64", "body_sha256", "truncated"}


def verify_cassette(
    path: Path,
    redact_headers: List[str],
    schema_version: int,
    body_patterns: Optional[List[Dict[str, str]]] = None,
) -> List[str]:
    errors: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"{path}: invalid json: {exc}"]
    if not isinstance(data, dict):
        return [f"{path}: cassette root is not an object"]
    if data.get("schema_version") != schema_version:
        errors.append(f"{path}: schema_version mismatch")
    interactions = data.get("interactions")
    if not isinstance(interactions, list):
        errors.append(f"{path}: interactions is not a list")
        return errors
    forbidden = {h.lower() for h in redact_headers}
    patterns = body_patterns or []
    for idx, interaction in enumerate(interactions):
        location = f"{path}: interaction {idx}"
        if not isinstance(interaction, dict):
            errors.append(f"{location} is not an object")
            continue
        request = interaction.get("request")
        response = interaction.get("response")
        timing = interaction.get("timing")
        for side, record, required in (
            ("request", request, REQUIRED_REQUEST_KEYS),
            ("response", response, REQUIRED_RESPONSE_KEYS),
        ):
            if not isinstance(record, dict):
                errors.append(f"{location} {side} is not an object")
                continue
            if not required.issubset(record):
                errors.append(f"{location} {side} missing keys")
            if side == "request":
                _verify_url(record.get("url"), f"{location} request", errors)
            _verify_headers(record.get("headers"), forbidden, f"{location} {side}", errors)
            _verify_body(record.get("body_b64"), patterns, f"{location} {side}", errors)
        if not isinstance(timing, dict) or "started_at" not in timing or "duration_ms" not in timing:
            errors.append(f"{location} timing missing keys")
    return errors


def _verify_url(url: object, location: str, errors: List[str]) -> None:
    if not isinstance(url, str):
        errors.append(f"{location} url invalid")
        return
    try:
        parts = urlsplit(url)
        if any(
            value is not None and unquote(value) != REDACTION_MARKER
            for value in (parts.username, parts.password)
        ):
            errors.append(f"{location} url contains userinfo")
        for name in exposed_query_keys(url):
            errors.append(f"{location} url query parameter not redacted: {name}")
    except ValueError:
        errors.append(f"{location} url invalid")


def _verify_headers(headers: object, forbidden: set[str], location: str, errors: List[str]) -> None:
    if not isinstance(headers, dict):
        errors.append(f"{location} headers invalid")
        return
    for name, values in headers.items():
        if not isinstance(name, str) or not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            errors.append(f"{location} headers invalid")
            continue
        if name.lower() in forbidden and any(value != REDACTION_MARKER for value in values):
            errors.append(f"{location} header not redacted: {name}")
        if name.lower() == "host":
            for value in values:
                if "@" not in value:
                    continue
                try:
                    if redact_url(f"//{value}")[2:] != value:
                        errors.append(f"{location} header contains unredacted userinfo: {name}")
                except ValueError:
                    errors.append(f"{location} header invalid: {name}")


def _verify_body(body_b64: object, patterns: List[Dict[str, str]], location: str, errors: List[str]) -> None:
    if not isinstance(body_b64, str):
        errors.append(f"{location} body_b64 invalid")
        return
    try:
        body = base64.b64decode(body_b64, validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        errors.append(f"{location} body_b64 invalid")
        return
    try:
        if redact_body(body, patterns) != body:
            errors.append(f"{location} body contains unredacted configured pattern")
    except (KeyError, TypeError, ValueError, re.error) as exc:
        errors.append(f"{location} body redaction configuration invalid: {type(exc).__name__}")
