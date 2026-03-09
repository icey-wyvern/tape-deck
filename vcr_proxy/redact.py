import re
from typing import Dict, Iterable, List, Tuple


def redact_headers(
    headers: Iterable[Tuple[str, str]],
    redact_list: List[str],
) -> List[Tuple[str, str]]:
    redact = {h.lower() for h in redact_list}
    cleaned: List[Tuple[str, str]] = []
    for name, value in headers:
        if name.lower() in redact:
            cleaned.append((name, "***"))
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
