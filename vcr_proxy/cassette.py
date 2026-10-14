import base64
import binascii
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from .config import Config


class CassetteError(Exception):
    pass


class CassetteWriteError(CassetteError):
    pass


_append_locks: Dict[Path, threading.Lock] = {}
_append_locks_guard = threading.Lock()


def _append_lock(path: Path) -> threading.Lock:
    key = Path(os.path.normcase(os.path.abspath(path)))
    with _append_locks_guard:
        return _append_locks.setdefault(key, threading.Lock())


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class Interaction:
    request: Dict[str, Any]
    response: Dict[str, Any]
    timing: Dict[str, Any]


def load_cassette(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CassetteError("cannot read cassette JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("interactions"), list):
        raise CassetteError("invalid cassette structure")
    for item in data["interactions"]:
        if not isinstance(item, dict):
            raise CassetteError("invalid cassette interaction")
        request = item.get("request")
        response = item.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            raise CassetteError("invalid cassette interaction")
        if not isinstance(request.get("method"), str) or not isinstance(request.get("url"), str):
            raise CassetteError("invalid cassette request")
        if not isinstance(response.get("status"), int) or not isinstance(response.get("reason"), str):
            raise CassetteError("invalid cassette response")
        if not _valid_headers(request.get("headers")) or not _valid_headers(response.get("headers")):
            raise CassetteError("invalid cassette headers")
        for record in (request, response):
            body_b64 = record.get("body_b64")
            if not isinstance(body_b64, str):
                raise CassetteError("invalid cassette body")
            try:
                base64.b64decode(body_b64, validate=True)
            except (ValueError, UnicodeError, binascii.Error) as exc:
                raise CassetteError("invalid cassette body") from exc
    return data


def _valid_headers(headers: Any) -> bool:
    return isinstance(headers, dict) and all(
        isinstance(name, str) and isinstance(values, list) and all(isinstance(value, str) for value in values)
        for name, values in headers.items()
    )


def write_cassette(path: Path, data: Dict[str, Any]) -> None:
    try:
        text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    except (TypeError, ValueError) as exc:
        raise CassetteWriteError("invalid cassette data") from exc
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise CassetteWriteError("could not write cassette") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def append_interaction(path: Path, cfg: Config, interaction: Dict[str, Any]) -> None:
    with _append_lock(path):
        cassette = load_cassette(path) if path.exists() else new_cassette(cfg)
        if cassette.get("schema_version") != cfg.cassette["schema_version"]:
            raise CassetteError("cassette schema_version mismatch")
        cassette["interactions"].append(interaction)
        write_cassette(path, cassette)


def cassette_path(cfg: Config, host: str) -> Path:
    strategy = cfg.cassette["file_strategy"]
    if strategy == "single":
        return cfg.cassette_dir / "cassette.json"
    safe_host = host.replace(":", "_")
    return cfg.cassette_dir / f"{safe_host}.json"


def new_cassette(cfg: Config) -> Dict[str, Any]:
    return {"schema_version": cfg.cassette["schema_version"], "interactions": []}
