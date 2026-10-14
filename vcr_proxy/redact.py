import re
from typing import Dict, Iterable, List, Tuple
from urllib.parse import unquote_plus, urlsplit, urlunsplit

REDACTION_MARKER = "***"
SENSITIVE_QUERY_KEYS = {
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "apikey",
    "key",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "auth",
    "authorization",
}


def _sensitive_query_key(name: str) -> bool:
    return re.sub(r"[-_]", "", unquote_plus(name)).lower() in SENSITIVE_QUERY_KEYS


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, host = netloc.rpartition("@")
        marker = f"{REDACTION_MARKER}:{REDACTION_MARKER}" if ":" in userinfo else REDACTION_MARKER
        netloc = f"{marker}@{host}"
    if not parts.query and netloc == parts.netloc:
        return url
    fields = []
    for field in parts.query.split("&"):
        name, _, _value = field.partition("=")
        fields.append(f"{name}={REDACTION_MARKER}" if _sensitive_query_key(name) else field)
    return urlunsplit(parts._replace(netloc=netloc, query="&".join(fields)))


def exposed_query_keys(url: str) -> List[str]:
    exposed = []
    for field in urlsplit(url).query.split("&"):
        name, separator, value = field.partition("=")
        if _sensitive_query_key(name) and (not separator or unquote_plus(value) != REDACTION_MARKER):
            exposed.append(unquote_plus(name))
    return exposed


def redact_headers(
    headers: Iterable[Tuple[str, str]],
    redact_list: List[str],
) -> List[Tuple[str, str]]:
    redact = {h.lower() for h in redact_list}
    cleaned: List[Tuple[str, str]] = []
    for name, value in headers:
        if name.lower() in redact:
            cleaned.append((name, REDACTION_MARKER))
        elif name.lower() == "host" and "@" in value:
            cleaned.append((name, redact_url(f"//{value}")[2:]))
        else:
            cleaned.append((name, value))
    return cleaned


def redact_body(data: bytes, patterns: List[Dict[str, str]]) -> bytes:
    if not patterns:
        return data
    text = data.decode("utf-8", errors="surrogateescape")
    for item in patterns:
        text = re.sub(item["pattern"], item["replacement"], text)
    return text.encode("utf-8", errors="surrogateescape")
