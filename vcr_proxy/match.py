import base64
import hashlib
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize_headers(
    headers: Iterable[Tuple[str, str]],
    allowlist: List[str],
    denylist: List[str],
) -> Dict[str, List[str]]:
    allow = {h.lower() for h in allowlist}
    deny = {h.lower() for h in denylist}
    hop_by_hop = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"}
    result: Dict[str, List[str]] = {}
    for name, value in headers:
        key = name.lower()
        if key in hop_by_hop:
            continue
        if key in deny:
            continue
        if allow and key not in allow:
            continue
        result.setdefault(key, []).append(value)
    return result


def normalize_url(url: str, ignore_query_params: List[str]) -> str:
    ignore = set(ignore_query_params)
    parts = urlsplit(url)
    if not parts.query:
        return url
    items = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ignore]
    query = urlencode(items)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def body_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_match_key(
    cfg_match: Dict[str, Any],
    method: str,
    url: str,
    headers: Iterable[Tuple[str, str]],
    body: bytes,
) -> Dict[str, Any]:
    key: Dict[str, Any] = {}
    if cfg_match.get("method", True):
        key["method"] = method.upper()
    if cfg_match.get("url", True):
        key["url"] = normalize_url(url, cfg_match.get("ignore_query_params", []))
    key["headers"] = normalize_headers(
        headers,
        cfg_match.get("headers_allowlist", []),
        cfg_match.get("headers_denylist", []),
    )
    body_strategy = cfg_match.get("body", {}).get("strategy", "hash")
    if body_strategy == "exact":
        key["body_b64"] = base64.b64encode(body).decode("ascii")
    else:
        key["body_sha256"] = body_hash(body)
    key["body_strategy"] = body_strategy
    return key


def match_interaction(cfg_match: Dict[str, Any], incoming_key: Dict[str, Any], interaction: Dict[str, Any]) -> bool:
    request = interaction["request"]
    if incoming_key.get("method") and incoming_key["method"] != request["method"]:
        return False
    if incoming_key.get("url") and incoming_key["url"] != normalize_url(
        request["url"], cfg_match.get("ignore_query_params", [])
    ):
        return False
    expected_headers = normalize_headers(
        ((k, v) for k, values in request["headers"].items() for v in values),
        cfg_match.get("headers_allowlist", []),
        cfg_match.get("headers_denylist", []),
    )
    if incoming_key.get("headers") != expected_headers:
        return False
    if incoming_key.get("body_strategy") == "exact":
        body_b64 = request.get("body_b64", "")
        return bool(incoming_key.get("body_b64") == body_b64)
    return bool(incoming_key.get("body_sha256") == request.get("body_sha256"))
