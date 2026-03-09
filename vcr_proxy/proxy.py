import asyncio
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import h11

from . import cassette as cassette_io
from .cassette import b64encode_bytes
from .config import Config
from .match import body_hash, request_match_key, match_interaction
from .redact import redact_body, redact_headers
from .tls_manager import TlsManager


HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
}


class UpstreamTimeoutError(Exception):
    pass


class ProxyServer:
    def __init__(self, cfg: Config, mode: str) -> None:
        self.cfg = cfg
        self.mode = mode
        self._server: Optional[asyncio.base_events.Server] = None
        self._tls_manager: Optional[TlsManager] = None
        self._active_handlers: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=self.cfg.listen_host, port=self.cfg.listen_port
        )

    async def serve_forever(self) -> None:
        if not self._server:
            await self.start()
        assert self._server
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._active_handlers:
            await asyncio.gather(*self._active_handlers, return_exceptions=True)

    @property
    def bound_address(self) -> Tuple[str, int]:
        if not self._server or not self._server.sockets:
            return (self.cfg.listen_host, self.cfg.listen_port)
        host, port = self._server.sockets[0].getsockname()[:2]
        return (host, port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._active_handlers.add(task)
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            parts = request_line.decode("ascii", errors="ignore").strip().split(" ", 2)
            if len(parts) != 3:
                await _send_error(writer, 400, "Bad Request", b"invalid request line")
                return
            method, target, version = parts
            headers = await _read_headers(reader)
            if method.upper() == "CONNECT":
                await self._handle_connect(target, headers, reader, writer)
                return
            body = await _read_request_body(reader, headers)
            if not _is_proxy_form(target):
                await _send_error(writer, 400, "Bad Request", b"proxy-form url required")
                return
            if self.mode == "record":
                await self._handle_record(method, target, version, headers, body, writer)
            elif self.mode == "replay":
                await self._handle_replay(method, target, version, headers, body, writer)
            else:
                await _send_error(writer, 500, "Server Error", b"unknown mode")
        except UpstreamTimeoutError:
            await _send_error(writer, 504, "Gateway Timeout", b"upstream timed out")
        except TimeoutError:
            await _send_error(writer, 504, "Gateway Timeout", b"upstream timed out")
        except ValueError as exc:
            await _send_error(writer, 400, "Bad Request", str(exc).encode("ascii", errors="ignore"))
        except Exception:
            await _send_error(writer, 400, "Bad Request", b"proxy error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if task is not None:
                self._active_handlers.discard(task)

    async def _handle_record(
        self,
        method: str,
        target: str,
        version: str,
        headers: List[Tuple[str, str]],
        body: bytes,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        started_at = time.time()
        url = target
        upstream_host, upstream_port, path = _parse_target(target)
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(upstream_host, upstream_port),
            timeout=self.cfg.upstream_timeout_ms / 1000,
        )
        upstream_headers = _prepare_upstream_headers(headers, upstream_host, upstream_port)
        request = _format_request(method, path, version, upstream_headers, body)
        upstream_writer.write(request)
        if body:
            upstream_writer.write(body)
        await upstream_writer.drain()
        timeout_s = _timeout_seconds(self.cfg.upstream_timeout_ms)
        status_line = await _readline_with_timeout(upstream_reader, timeout_s)
        if not status_line:
            await _send_error(client_writer, 502, "Bad Gateway", b"upstream closed")
            return
        resp_headers = await _read_headers(upstream_reader, timeout_s)
        raw_header_bytes = _format_response_headers(status_line, resp_headers)
        client_writer.write(raw_header_bytes)
        await client_writer.drain()
        resp_body, _, resp_truncated = await _read_response_body(
            upstream_reader,
            resp_headers,
            client_writer,
            timeout_s,
        )
        duration_ms = int((time.time() - started_at) * 1000)
        upstream_writer.close()
        await upstream_writer.wait_closed()
        cassette_path = cassette_io.cassette_path(self.cfg, upstream_host)
        cassette = cassette_io.load_cassette(cassette_path) if cassette_path.exists() else cassette_io.new_cassette(self.cfg)
        redacted_headers = redact_headers(headers, self.cfg.redaction.get("headers", []))
        redacted_body = redact_body(body, self.cfg.redaction.get("body_patterns", []))
        stored_req_body = redacted_body
        redacted_resp_headers = redact_headers(resp_headers, self.cfg.redaction.get("headers", []))
        redacted_resp_body = redact_body(resp_body, self.cfg.redaction.get("body_patterns", []))
        stored_resp_body = redacted_resp_body
        interaction = {
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": _headers_to_dict(redacted_headers),
                "body_b64": b64encode_bytes(stored_req_body),
                "body_sha256": body_hash(redacted_body),
                "truncated": False,
            },
            "response": {
                "status": _parse_status(status_line),
                "reason": _parse_reason(status_line),
                "headers": _headers_to_dict(redacted_resp_headers),
                "body_b64": b64encode_bytes(stored_resp_body),
                "body_sha256": body_hash(redacted_resp_body),
                "truncated": resp_truncated,
            },
            "timing": {"started_at": started_at, "duration_ms": duration_ms},
        }
        cassette["interactions"].append(interaction)
        cassette_io.write_cassette(cassette_path, cassette)

    async def _handle_replay(
        self,
        method: str,
        target: str,
        version: str,
        headers: List[Tuple[str, str]],
        body: bytes,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        upstream_host, _, _ = _parse_target(target)
        cassette_path = cassette_io.cassette_path(self.cfg, upstream_host)
        if not cassette_path.exists():
            await _send_error(client_writer, 502, "Bad Gateway", b"no cassette")
            return
        cassette = cassette_io.load_cassette(cassette_path)
        redacted_headers = redact_headers(headers, self.cfg.redaction.get("headers", []))
        redacted_body = redact_body(body, self.cfg.redaction.get("body_patterns", []))
        incoming_key = request_match_key(self.cfg.match, method, target, redacted_headers, redacted_body)
        for interaction in cassette.get("interactions", []):
            if match_interaction(self.cfg.match, incoming_key, interaction):
                await _send_replay(client_writer, interaction)
                return
        await _send_error(client_writer, 502, "Bad Gateway", b"no matching interaction")

    async def _handle_connect(
        self,
        target: str,
        headers: List[Tuple[str, str]],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if not self.cfg.tls.get("enabled", False):
            await _send_error(writer, 400, "Bad Request", b"https not enabled")
            return
        try:
            host, port = _parse_connect_target(target)
        except ValueError:
            await _send_error(writer, 400, "Bad Request", b"invalid CONNECT target")
            return
        try:
            tls_manager = self._get_tls_manager()
        except FileNotFoundError:
            await _send_error(writer, 500, "Server Error", b"ca not initialized")
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        ctx = tls_manager.server_context(host)
        new_transport = await loop.start_tls(transport, protocol, ctx, server_side=True)
        tls_writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)
        try:
            await self._handle_https_session(reader, tls_writer, host, port)
        finally:
            try:
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                pass

    def _get_tls_manager(self) -> TlsManager:
        if self._tls_manager:
            return self._tls_manager
        tls = self.cfg.tls
        ca_dir = Path(tls["ca_dir"])
        ca_key = ca_dir / tls["ca_key"]
        ca_cert = ca_dir / tls["ca_cert"]
        leaf_dir = Path(tls["leaf_dir"])
        if not ca_key.exists() or not ca_cert.exists():
            raise FileNotFoundError("CA not initialized")
        self._tls_manager = TlsManager(ca_key, ca_cert, leaf_dir, tls.get("key_password"))
        return self._tls_manager

    async def _handle_https_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        server_conn = h11.Connection(h11.SERVER)
        while True:
            request = await _h11_read_request_event(reader, server_conn)
            if request is None:
                return
            method, target, headers = request
            if _header_value(headers, "transfer-encoding") == "chunked":
                await _send_h11_error(
                    writer, server_conn, 400, "Bad Request", b"chunked request bodies not supported"
                )
                return
            url = _https_url(host, port, target)
            if self.mode == "record":
                should_close = await self._handle_https_record(
                    method, target, url, headers, writer, server_conn, host, port, reader
                )
            else:
                should_close = await self._handle_https_replay(method, url, headers, writer, server_conn, reader, host)
            if should_close:
                return
            server_conn.start_next_cycle()

    async def _handle_https_record(
        self,
        method: str,
        target: str,
        url: str,
        headers: List[Tuple[str, str]],
        client_writer: asyncio.StreamWriter,
        server_conn: h11.Connection,
        host: str,
        port: int,
        client_reader: asyncio.StreamReader,
    ) -> bool:
        started_at = time.time()
        tls = self.cfg.tls
        tls_manager = self._get_tls_manager()
        upstream_ctx = tls_manager.upstream_context(
            verify=not tls.get("upstream_insecure", False),
            ca_bundle_path=Path(tls["upstream_ca_bundle"]) if tls.get("upstream_ca_bundle") else None,
        )
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=upstream_ctx, server_hostname=host),
            timeout=self.cfg.upstream_timeout_ms / 1000,
        )
        upstream_headers = _prepare_upstream_headers_https(headers, host, port)
        upstream_conn = h11.Connection(h11.CLIENT)
        await _h11_send_request_headers(upstream_writer, upstream_conn, method, target, upstream_headers)
        req_capture = _BodyCapture(
            self.cfg.redaction.get("body_patterns", []),
            _needs_full_body(self.cfg.match),
        )
        await _h11_stream_request_body(client_reader, server_conn, upstream_writer, upstream_conn, req_capture)
        timeout_s = _timeout_seconds(self.cfg.upstream_timeout_ms)
        response = await _h11_read_response_event(upstream_reader, upstream_conn, timeout_s)
        if response is None:
            await _send_h11_error(client_writer, server_conn, 502, "Bad Gateway", b"upstream closed")
            return True
        status, reason, resp_headers = response
        resp_capture = _BodyCapture(
            self.cfg.redaction.get("body_patterns", []),
            False,
        )
        await _h11_send_response_headers(client_writer, server_conn, status, reason, resp_headers)
        await _h11_stream_response_body(
            upstream_reader,
            upstream_conn,
            client_writer,
            server_conn,
            resp_capture,
            timeout_s,
        )
        upstream_writer.close()
        await upstream_writer.wait_closed()
        duration_ms = int((time.time() - started_at) * 1000)
        req_record = req_capture.finish()
        resp_record = resp_capture.finish()
        redacted_headers = redact_headers(headers, self.cfg.redaction.get("headers", []))
        redacted_resp_headers = redact_headers(resp_headers, self.cfg.redaction.get("headers", []))
        interaction = {
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": _headers_to_dict(redacted_headers),
                "body_b64": b64encode_bytes(req_record.body_bytes),
                "body_sha256": req_record.body_sha256,
                "truncated": req_record.truncated,
            },
            "response": {
                "status": status,
                "reason": reason,
                "headers": _headers_to_dict(redacted_resp_headers),
                "body_b64": b64encode_bytes(resp_record.body_bytes),
                "body_sha256": resp_record.body_sha256,
                "truncated": resp_record.truncated,
            },
            "timing": {"started_at": started_at, "duration_ms": duration_ms},
        }
        cassette_path = cassette_io.cassette_path(self.cfg, host)
        cassette = cassette_io.load_cassette(cassette_path) if cassette_path.exists() else cassette_io.new_cassette(self.cfg)
        cassette["interactions"].append(interaction)
        cassette_io.write_cassette(cassette_path, cassette)
        client_close = _header_has_token(headers, "connection", "close")
        resp_close = _header_has_token(resp_headers, "connection", "close")
        return client_close or resp_close

    async def _handle_https_replay(
        self,
        method: str,
        url: str,
        headers: List[Tuple[str, str]],
        client_writer: asyncio.StreamWriter,
        server_conn: h11.Connection,
        client_reader: asyncio.StreamReader,
        host: str,
    ) -> bool:
        cassette_path = cassette_io.cassette_path(self.cfg, host)
        if not cassette_path.exists():
            await _send_h11_error(client_writer, server_conn, 502, "Bad Gateway", b"no cassette")
            return True
        cassette = cassette_io.load_cassette(cassette_path)
        req_capture = _BodyCapture(
            self.cfg.redaction.get("body_patterns", []),
            _needs_full_body(self.cfg.match),
        )
        await _h11_stream_request_body(client_reader, server_conn, None, None, req_capture)
        req_record = req_capture.finish()
        redacted_headers = redact_headers(headers, self.cfg.redaction.get("headers", []))
        incoming_key = _build_incoming_key(self.cfg.match, method, url, redacted_headers, req_record)
        for interaction in cassette.get("interactions", []):
            if match_interaction(self.cfg.match, incoming_key, interaction):
                resp = interaction["response"]
                body = cassette_io.b64decode_bytes(resp.get("body_b64", ""))
                headers = _dict_to_headers(resp.get("headers", {}))
                await _h11_send_response(
                    client_writer, server_conn, resp["status"], resp["reason"], headers, body, force_content_length=True
                )
                client_close = _header_has_token(headers, "connection", "close")
                return client_close
        await _send_h11_error(client_writer, server_conn, 502, "Bad Gateway", b"no matching interaction")
        return True


def _parse_status(line: bytes) -> int:
    try:
        return int(line.decode("ascii", errors="ignore").split(" ", 2)[1])
    except Exception:
        return 502


def _parse_reason(line: bytes) -> str:
    try:
        return line.decode("ascii", errors="ignore").split(" ", 2)[2].strip()
    except Exception:
        return "Bad Gateway"


def _format_request(method: str, path: str, version: str, headers: List[Tuple[str, str]], body: bytes) -> bytes:
    lines = [f"{method} {path} {version}"]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    if body and not any(name.lower() == "content-length" for name, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii")


def _format_response_headers(status_line: bytes, headers: List[Tuple[str, str]]) -> bytes:
    lines = [status_line.decode("ascii", errors="ignore").rstrip("\r\n")]
    for name, value in headers:
        if name.lower() in ("connection", "proxy-connection", "keep-alive"):
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii")


def _headers_to_dict(headers: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for name, value in headers:
        key = name.lower()
        result.setdefault(key, []).append(value)
    return result


def _header_has_token(headers: List[Tuple[str, str]], name: str, token: str) -> bool:
    value = _header_value(headers, name)
    if not value:
        return False
    return token.lower() in [part.strip().lower() for part in value.split(",")]


def _prepare_upstream_headers(
    headers: List[Tuple[str, str]], host: str, port: int
) -> List[Tuple[str, str]]:
    cleaned: List[Tuple[str, str]] = []
    has_host = False
    for name, value in headers:
        if name.lower() in HOP_BY_HOP:
            continue
        if name.lower() == "host":
            has_host = True
        cleaned.append((name, value))
    if not has_host:
        host_value = host if port in (80, 443) else f"{host}:{port}"
        cleaned.append(("Host", host_value))
    cleaned.append(("Connection", "close"))
    return cleaned


def _prepare_upstream_headers_https(
    headers: List[Tuple[str, str]], host: str, port: int
) -> List[Tuple[str, str]]:
    cleaned: List[Tuple[str, str]] = []
    has_host = False
    for name, value in headers:
        if name.lower() in HOP_BY_HOP:
            continue
        if name.lower() == "host":
            has_host = True
        cleaned.append((name, value))
    if not has_host:
        host_value = host if port == 443 else f"{host}:{port}"
        cleaned.append(("Host", host_value))
    return cleaned


async def _read_headers(reader: asyncio.StreamReader, timeout_s: Optional[float] = None) -> List[Tuple[str, str]]:
    headers: List[Tuple[str, str]] = []
    while True:
        line = await _readline_with_timeout(reader, timeout_s)
        if not line:
            break
        if line in (b"\r\n", b"\n"):
            break
        if b":" not in line:
            continue
        name, value = line.decode("ascii", errors="ignore").split(":", 1)
        headers.append((name.strip(), value.strip()))
    return headers


def _header_value(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    for h_name, h_value in headers:
        if h_name.lower() == name.lower():
            return h_value
    return None


async def _read_request_body(reader: asyncio.StreamReader, headers: List[Tuple[str, str]]) -> bytes:
    if _header_value(headers, "transfer-encoding") == "chunked":
        raise ValueError("chunked request bodies are not supported")
    length = _header_value(headers, "content-length")
    if not length:
        return b""
    return await reader.readexactly(int(length))


async def _read_response_body(
    reader: asyncio.StreamReader,
    headers: List[Tuple[str, str]],
    client_writer: asyncio.StreamWriter,
    timeout_s: Optional[float] = None,
) -> Tuple[bytes, str, bool]:
    transfer = _header_value(headers, "transfer-encoding")
    if transfer and transfer.lower() == "chunked":
        return await _read_chunked(reader, client_writer, timeout_s)
    length = _header_value(headers, "content-length")
    if length is None:
        return await _read_until_close(reader, client_writer, timeout_s)
    return await _read_fixed_length(reader, client_writer, int(length), timeout_s)


async def _read_fixed_length(
    reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    length: int,
    timeout_s: Optional[float] = None,
) -> Tuple[bytes, str, bool]:
    remaining = length
    collected = bytearray()
    hasher = _sha256()
    while remaining > 0:
        chunk = await _read_with_timeout(reader, min(65536, remaining), timeout_s)
        if not chunk:
            break
        remaining -= len(chunk)
        hasher.update(chunk)
        collected.extend(chunk)
        client_writer.write(chunk)
        await client_writer.drain()
    return bytes(collected), hasher.hexdigest(), False


async def _read_until_close(
    reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    timeout_s: Optional[float] = None,
) -> Tuple[bytes, str, bool]:
    collected = bytearray()
    hasher = _sha256()
    while True:
        chunk = await _read_with_timeout(reader, 65536, timeout_s)
        if not chunk:
            break
        hasher.update(chunk)
        collected.extend(chunk)
        client_writer.write(chunk)
        await client_writer.drain()
    return bytes(collected), hasher.hexdigest(), False


async def _read_chunked(
    reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    timeout_s: Optional[float] = None,
) -> Tuple[bytes, str, bool]:
    collected = bytearray()
    hasher = _sha256()
    while True:
        size_line = await _readline_with_timeout(reader, timeout_s)
        if not size_line:
            break
        client_writer.write(size_line)
        await client_writer.drain()
        size_str = size_line.strip().split(b";", 1)[0]
        try:
            size = int(size_str, 16)
        except ValueError:
            size = 0
        if size == 0:
            while True:
                trailer = await _readline_with_timeout(reader, timeout_s)
                if not trailer:
                    break
                client_writer.write(trailer)
                await client_writer.drain()
                if trailer in (b"\r\n", b"\n"):
                    break
            break
        chunk = await _readexactly_with_timeout(reader, size, timeout_s)
        crlf = await _readexactly_with_timeout(reader, 2, timeout_s)
        hasher.update(chunk)
        collected.extend(chunk)
        client_writer.write(chunk + crlf)
        await client_writer.drain()
    return bytes(collected), hasher.hexdigest(), False


def _sha256():
    return hashlib.sha256()


def _timeout_seconds(timeout_ms: int) -> Optional[float]:
    if timeout_ms <= 0:
        return None
    return timeout_ms / 1000


async def _read_with_timeout(
    reader: asyncio.StreamReader,
    size: int,
    timeout_s: Optional[float],
) -> bytes:
    return await _wait_for_io(reader.read(size), timeout_s)


async def _readexactly_with_timeout(
    reader: asyncio.StreamReader,
    size: int,
    timeout_s: Optional[float],
) -> bytes:
    return await _wait_for_io(reader.readexactly(size), timeout_s)


async def _readline_with_timeout(reader: asyncio.StreamReader, timeout_s: Optional[float]) -> bytes:
    return await _wait_for_io(reader.readline(), timeout_s)


async def _wait_for_io(awaitable: Any, timeout_s: Optional[float]) -> Any:
    if timeout_s is None:
        return await awaitable
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout_s)
    except TimeoutError as exc:
        raise UpstreamTimeoutError("upstream timed out") from exc


def _parse_target(target: str) -> Tuple[str, int, str]:
    parts = urlsplit(target)
    if parts.scheme and parts.scheme.lower() != "http":
        raise ValueError("use CONNECT for https")
    host = parts.hostname or ""
    if not host:
        raise ValueError("host missing")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return host, port, path


def _is_proxy_form(target: str) -> bool:
    parts = urlsplit(target)
    return bool(parts.scheme and parts.netloc)


async def _send_replay(writer: asyncio.StreamWriter, interaction: Dict[str, Dict]) -> None:
    resp = interaction["response"]
    status = resp["status"]
    reason = resp["reason"]
    body = cassette_io.b64decode_bytes(resp.get("body_b64", ""))
    headers = resp.get("headers", {})
    flat_headers: List[Tuple[str, str]] = []
    for name, values in headers.items():
        if name.lower() == "transfer-encoding":
            continue
        if name.lower() in ("connection", "proxy-connection", "keep-alive"):
            continue
        for value in values:
            flat_headers.append((name, value))
    flat_headers = [(k, v) for k, v in flat_headers if k.lower() != "content-length"]
    flat_headers.append(("Content-Length", str(len(body))))
    flat_headers.append(("Connection", "close"))
    lines = [f"HTTP/1.1 {status} {reason}"]
    for name, value in flat_headers:
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    writer.write("\r\n".join(lines).encode("ascii") + body)
    await writer.drain()


async def _send_error(writer: asyncio.StreamWriter, status: int, reason: str, body: bytes) -> None:
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}", "Connection: close", "", ""]
    try:
        writer.write("\r\n".join(lines).encode("ascii") + body)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        return


def _parse_connect_target(target: str) -> Tuple[str, int]:
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        if not host:
            raise ValueError("host missing")
        return host, int(port_str)
    if not target:
        raise ValueError("host missing")
    return target, 443


def _https_url(host: str, port: int, target: str) -> str:
    netloc = host if port == 443 else f"{host}:{port}"
    if target.startswith("http://") or target.startswith("https://"):
        return target
    if not target.startswith("/"):
        target = f"/{target}"
    return f"https://{netloc}{target}"


def _dict_to_headers(headers: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    flat: List[Tuple[str, str]] = []
    for name, values in headers.items():
        for value in values:
            flat.append((name, value))
    return flat


async def _h11_read_request_event(
    reader: asyncio.StreamReader, conn: h11.Connection
) -> Optional[Tuple[str, str, List[Tuple[str, str]]]]:
    while True:
        event = await _h11_next_event(reader, conn)
        if event is None or isinstance(event, h11.ConnectionClosed):
            return None
        if isinstance(event, h11.Request):
            headers = [(k.decode("ascii", "ignore"), v.decode("ascii", "ignore")) for k, v in event.headers]
            return event.method.decode("ascii", "ignore"), event.target.decode("ascii", "ignore"), headers


async def _h11_read_response_event(
    reader: asyncio.StreamReader,
    conn: h11.Connection,
    timeout_s: Optional[float] = None,
) -> Optional[Tuple[int, str, List[Tuple[str, str]]]]:
    while True:
        event = await _h11_next_event(reader, conn, timeout_s)
        if event is None or isinstance(event, h11.ConnectionClosed):
            return None
        if isinstance(event, h11.Response):
            headers = [(k.decode("ascii", "ignore"), v.decode("ascii", "ignore")) for k, v in event.headers]
            reason = event.reason.decode("ascii", "ignore") if event.reason else ""
            return event.status_code, reason, headers


async def _h11_next_event(
    reader: asyncio.StreamReader,
    conn: h11.Connection,
    timeout_s: Optional[float] = None,
) -> Optional[h11.Event]:
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = await _read_with_timeout(reader, 65536, timeout_s)
            if not data:
                conn.receive_data(b"")
                return conn.next_event()
            conn.receive_data(data)
            continue
        return event


async def _h11_send_request_headers(
    writer: asyncio.StreamWriter,
    conn: h11.Connection,
    method: str,
    target: str,
    headers: List[Tuple[str, str]],
) -> None:
    req_headers = _normalize_request_headers(headers)
    request = h11.Request(method=method, target=target, headers=req_headers)
    writer.write(conn.send(request))
    await writer.drain()


async def _h11_send_response(
    writer: asyncio.StreamWriter,
    conn: h11.Connection,
    status: int,
    reason: str,
    headers: List[Tuple[str, str]],
    body: bytes,
    force_content_length: bool = False,
) -> None:
    resp_headers = _normalize_response_headers(headers, body, force_content_length, passthrough=False)
    response = h11.Response(status_code=status, reason=reason, headers=resp_headers)
    writer.write(conn.send(response))
    if body:
        writer.write(conn.send(h11.Data(data=body)))
    writer.write(conn.send(h11.EndOfMessage()))
    await writer.drain()


async def _send_h11_response(
    writer: asyncio.StreamWriter,
    conn: h11.Connection,
    status: int,
    reason: str,
    headers: List[Tuple[str, str]],
    body: bytes,
    force_content_length: bool = False,
) -> None:
    await _h11_send_response(writer, conn, status, reason, headers, body, force_content_length)


async def _send_h11_error(
    writer: asyncio.StreamWriter,
    conn: h11.Connection,
    status: int,
    reason: str,
    body: bytes,
) -> None:
    headers = [("Content-Length", str(len(body))), ("Connection", "close")]
    response = h11.Response(status_code=status, reason=reason, headers=headers)
    writer.write(conn.send(response))
    if body:
        writer.write(conn.send(h11.Data(data=body)))
    writer.write(conn.send(h11.EndOfMessage()))
    await writer.drain()


def _normalize_request_headers(headers: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    cleaned: List[Tuple[str, str]] = []
    for name, value in headers:
        if name.lower() in HOP_BY_HOP:
            continue
        cleaned.append((name, value))
    return cleaned


def _normalize_response_headers(
    headers: List[Tuple[str, str]], body: bytes, force_content_length: bool, passthrough: bool
) -> List[Tuple[str, str]]:
    cleaned: List[Tuple[str, str]] = []
    for name, value in headers:
        if name.lower() == "proxy-connection":
            continue
        if not passthrough:
            if name.lower() == "transfer-encoding":
                continue
            if name.lower() == "content-length":
                continue
        cleaned.append((name, value))
    if force_content_length:
        cleaned.append(("Content-Length", str(len(body))))
    return cleaned


class _BodyCapture:
    def __init__(self, redact_patterns: List[Dict[str, str]], keep_full: bool) -> None:
        self._redact_patterns = redact_patterns
        self._hasher = _sha256()
        self._stored = bytearray()
        self._keep_full = keep_full

    def feed(self, chunk: bytes) -> None:
        self._hasher.update(chunk)
        self._stored.extend(chunk)

    def finish(self) -> "_BodyRecord":
        full_bytes = bytes(self._stored)
        if self._redact_patterns:
            redacted_full = redact_body(full_bytes, self._redact_patterns)
        else:
            redacted_full = full_bytes
        return _BodyRecord(
            body_bytes=redacted_full,
            body_sha256=body_hash(redacted_full),
            truncated=False,
            redacted_full=redacted_full if self._keep_full else b"",
        )


class _BodyRecord:
    def __init__(self, body_bytes: bytes, body_sha256: str, truncated: bool, redacted_full: bytes) -> None:
        self.body_bytes = body_bytes
        self.body_sha256 = body_sha256
        self.truncated = truncated
        self.redacted_full = redacted_full


def _needs_full_body(cfg_match: Dict[str, Any]) -> bool:
    return cfg_match.get("body", {}).get("strategy", "hash") == "exact"


def _build_incoming_key(
    cfg_match: Dict[str, Any],
    method: str,
    url: str,
    headers: List[Tuple[str, str]],
    body_record: _BodyRecord,
) -> Dict[str, Any]:
    key = request_match_key(cfg_match, method, url, headers, body_record.redacted_full)
    strategy = cfg_match.get("body", {}).get("strategy", "hash")
    if strategy == "hash":
        key["body_sha256"] = body_record.body_sha256
        key.pop("body_b64", None)
    return key


async def _h11_stream_request_body(
    reader: asyncio.StreamReader,
    server_conn: h11.Connection,
    upstream_writer: Optional[asyncio.StreamWriter],
    upstream_conn: Optional[h11.Connection],
    capture: _BodyCapture,
) -> None:
    while True:
        event = await _h11_next_event(reader, server_conn)
        if event is None or isinstance(event, h11.ConnectionClosed):
            return
        if isinstance(event, h11.Data):
            capture.feed(event.data)
            if upstream_writer and upstream_conn:
                upstream_writer.write(upstream_conn.send(h11.Data(data=event.data)))
                await upstream_writer.drain()
        if isinstance(event, h11.EndOfMessage):
            if upstream_writer and upstream_conn:
                upstream_writer.write(upstream_conn.send(h11.EndOfMessage()))
                await upstream_writer.drain()
            return


async def _h11_send_response_headers(
    writer: asyncio.StreamWriter,
    conn: h11.Connection,
    status: int,
    reason: str,
    headers: List[Tuple[str, str]],
) -> None:
    resp_headers = _normalize_response_headers(headers, b"", False, passthrough=True)
    response = h11.Response(status_code=status, reason=reason, headers=resp_headers)
    writer.write(conn.send(response))
    await writer.drain()


async def _h11_stream_response_body(
    upstream_reader: asyncio.StreamReader,
    upstream_conn: h11.Connection,
    client_writer: asyncio.StreamWriter,
    server_conn: h11.Connection,
    capture: _BodyCapture,
    timeout_s: Optional[float] = None,
) -> None:
    while True:
        event = await _h11_next_event(upstream_reader, upstream_conn, timeout_s)
        if event is None or isinstance(event, h11.ConnectionClosed):
            return
        if isinstance(event, h11.Data):
            capture.feed(event.data)
            client_writer.write(server_conn.send(h11.Data(data=event.data)))
            await client_writer.drain()
        if isinstance(event, h11.EndOfMessage):
            client_writer.write(server_conn.send(h11.EndOfMessage()))
            await client_writer.drain()
            return
