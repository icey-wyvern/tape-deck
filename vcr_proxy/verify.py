import json
from pathlib import Path
from typing import Dict, List


REQUIRED_REQUEST_KEYS = {"method", "url", "headers", "body_b64", "body_sha256", "truncated"}
REQUIRED_RESPONSE_KEYS = {"status", "reason", "headers", "body_b64", "body_sha256", "truncated"}


def verify_cassette(path: Path, redact_headers: List[str], schema_version: int) -> List[str]:
    errors: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: invalid json: {exc}"]
    if data.get("schema_version") != schema_version:
        errors.append(f"{path}: schema_version mismatch")
    interactions = data.get("interactions")
    if not isinstance(interactions, list):
        errors.append(f"{path}: interactions is not a list")
        return errors
    forbidden = {h.lower() for h in redact_headers}
    for idx, interaction in enumerate(interactions):
        req = interaction.get("request", {})
        resp = interaction.get("response", {})
        timing = interaction.get("timing", {})
        if not REQUIRED_REQUEST_KEYS.issubset(req.keys()):
            errors.append(f"{path}: interaction {idx} request missing keys")
        if not REQUIRED_RESPONSE_KEYS.issubset(resp.keys()):
            errors.append(f"{path}: interaction {idx} response missing keys")
        if "started_at" not in timing or "duration_ms" not in timing:
            errors.append(f"{path}: interaction {idx} timing missing keys")
        for side, headers in (("request", req.get("headers", {})), ("response", resp.get("headers", {}))):
            if not isinstance(headers, dict):
                errors.append(f"{path}: interaction {idx} {side} headers invalid")
                continue
            for name, values in headers.items():
                if name.lower() in forbidden:
                    if any(value != "***" for value in values):
                        errors.append(f"{path}: interaction {idx} {side} header not redacted: {name}")
    return errors
