import asyncio
import base64
import http.client
import json
import os
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

import h11
import pytest
import trustme

from vcr_proxy import cassette as cassette_io
from vcr_proxy.config import load_config
from vcr_proxy.pytest_helper import proxy_context
from vcr_proxy.redact import REDACTION_MARKER, redact_url
from vcr_proxy.tls_ca import init_ca
from vcr_proxy.verify import verify_cassette


class UpstreamThread:
    def __init__(self, keep_alive: bool = False) -> None:
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[asyncio.base_events.Server] = None
        self._serve_task: Optional[asyncio.Task] = None
        self._started = threading.Event()
        self._bound: Optional[Tuple[str, int]] = None
        self._keep_alive = keep_alive
        self.last_path: Optional[str] = None
        self.last_headers: List[Tuple[str, str]] = []
        self._sequence = 0

    def start(self) -> Tuple[str, int]:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)
        if not self._bound:
            raise RuntimeError("upstream failed to start")
        return self._bound

    def stop(self) -> None:
        if not self._loop or not self._server or not self._thread or not self._thread.is_alive():
            return

        loop = self._loop
        server = self._server
        if loop.is_closed():
            return

        async def _shutdown() -> None:
            server.close()
            await server.wait_closed()
            if self._serve_task and not self._serve_task.done():
                self._serve_task.cancel()
            current = asyncio.current_task(loop=loop)
            pending = [task for task in asyncio.all_tasks(loop) if not task.done() and task is not current]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=2)
            loop.stop()

        fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
        try:
            fut.result(timeout=5)
        except Exception:
            if not loop.is_closed():
                loop.call_soon_threadsafe(loop.stop)
        self._thread.join(timeout=5)

    async def _handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return
        parts = request_line.decode("ascii", errors="ignore").strip().split(" ", 2)
        if len(parts) != 3:
            writer.close()
            return
        method, path, _version = parts
        self.last_path = path
        headers = await _read_headers(reader)
        self.last_headers = headers
        body = b""
        length = _header_value(headers, "content-length")
        if length:
            body = await reader.readexactly(int(length))
        if path.startswith("/hello"):
            await _send_content_length(writer, 200, b"hello", close=not self._keep_alive)
        elif path == "/sequence":
            self._sequence += 1
            await _send_content_length(
                writer, 200, f"response-{self._sequence}".encode("ascii"), close=not self._keep_alive
            )
        elif path.startswith("/sensitive-headers"):
            await _send_content_length(
                writer,
                200,
                b"hello",
                close=not self._keep_alive,
                extra_headers=[("Set-Cookie", "session=synthetic-cookie"), ("X-API-Key", "synthetic-key")],
            )
        elif path.startswith("/echo") and method.upper() == "POST":
            await _send_content_length(writer, 200, body, close=not self._keep_alive)
        elif path.startswith("/chunked"):
            await _send_chunked(writer, 200, [b"chunk-one", b"chunk-two"], close=not self._keep_alive)
        else:
            await _send_content_length(writer, 404, b"missing", close=not self._keep_alive)
        writer.close()
        await writer.wait_closed()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def _serve() -> None:
            self._server = await asyncio.start_server(self._handler, host="127.0.0.1", port=0)
            sock = self._server.sockets[0].getsockname()
            self._bound = (sock[0], sock[1])
            self._started.set()
            await self._server.serve_forever()

        try:
            self._serve_task = loop.create_task(_serve())
            loop.run_forever()
        finally:
            loop.close()


async def _send_content_length(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    close: bool = True,
    extra_headers: Optional[List[Tuple[str, str]]] = None,
) -> None:
    lines = [
        f"HTTP/1.1 {status} OK",
        f"Content-Length: {len(body)}",
        "Connection: close" if close else "Connection: keep-alive",
        "",
        "",
    ]
    if extra_headers:
        lines[-2:-2] = [f"{name}: {value}" for name, value in extra_headers]
    writer.write("\r\n".join(lines).encode("ascii") + body)
    await writer.drain()


async def _send_chunked(writer: asyncio.StreamWriter, status: int, chunks: List[bytes], close: bool = True) -> None:
    lines = [
        f"HTTP/1.1 {status} OK",
        "Transfer-Encoding: chunked",
        "Connection: close" if close else "Connection: keep-alive",
        "",
        "",
    ]
    writer.write("\r\n".join(lines).encode("ascii"))
    for chunk in chunks:
        writer.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
    writer.write(b"0\r\n\r\n")
    await writer.drain()


async def _read_headers(reader: asyncio.StreamReader) -> List[Tuple[str, str]]:
    headers: List[Tuple[str, str]] = []
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
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


def _write_config(tmp_path: Path, match_overrides: Optional[Dict[str, Any]] = None) -> Path:
    config = {
        "listen": {"host": "127.0.0.1", "port": 0},
        "cassette_dir": str(tmp_path / "cassettes"),
        "limits": {"upstream_timeout_ms": 30000},
        "match": {
            "method": True,
            "url": True,
            "ignore_query_params": [],
            "headers_allowlist": [],
            "headers_denylist": [],
            "body": {"strategy": "hash"},
        },
        "redaction": {
            "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
            "body_patterns": [{"pattern": "secret", "replacement": "***"}],
        },
        "cassette": {"file_strategy": "single", "schema_version": 1},
        "tls": {
            "enabled": False,
            "ca_dir": str(tmp_path / "ca"),
            "ca_key": "ca.key",
            "ca_cert": "ca.crt",
            "leaf_dir": str(tmp_path / "ca" / "leaf"),
            "key_password": None,
            "upstream_insecure": False,
            "upstream_ca_bundle": None,
        },
    }
    if match_overrides:
        config["match"].update(match_overrides)
    path = tmp_path / ".vcr-proxy.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_config_with_limits(
    tmp_path: Path,
    upstream_timeout_ms: int,
    match_overrides: Optional[Dict[str, Any]] = None,
) -> Path:
    path = _write_config(tmp_path, match_overrides=match_overrides)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["limits"]["upstream_timeout_ms"] = upstream_timeout_ms
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_tls_config(tmp_path: Path, match_overrides: Optional[Dict[str, Any]] = None) -> Path:
    config = {
        "listen": {"host": "127.0.0.1", "port": 0},
        "cassette_dir": str(tmp_path / "cassettes"),
        "limits": {"upstream_timeout_ms": 30000},
        "match": {
            "method": True,
            "url": True,
            "ignore_query_params": [],
            "headers_allowlist": [],
            "headers_denylist": [],
            "body": {"strategy": "hash"},
        },
        "redaction": {
            "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
            "body_patterns": [{"pattern": "secret", "replacement": "***"}],
        },
        "cassette": {"file_strategy": "single", "schema_version": 1},
        "tls": {
            "enabled": True,
            "ca_dir": str(tmp_path / "ca"),
            "ca_key": "ca.key",
            "ca_cert": "ca.crt",
            "leaf_dir": str(tmp_path / "ca" / "leaf"),
            "key_password": None,
            "upstream_insecure": True,
            "upstream_ca_bundle": None,
        },
    }
    if match_overrides:
        config["match"].update(match_overrides)
    path = tmp_path / ".vcr-proxy.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


@contextmanager
def upstream_context() -> Iterator[Tuple[str, int]]:
    server = UpstreamThread()
    host, port = server.start()
    try:
        yield host, port
    finally:
        server.stop()


def _request(
    proxy_host: str,
    proxy_port: int,
    method: str,
    url: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[http.client.HTTPResponse, bytes]:
    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5)
    conn.request(method, url, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def _raw_http_request(host: str, port: int, request: bytes) -> bytes:
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(request)
    data = b""
    content_length = None
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            if content_length is None:
                header, _body = data.split(b"\r\n\r\n", 1)
                for line in header.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            content_length = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            content_length = 0
            if content_length is None:
                break
            if content_length is not None and len(data.split(b"\r\n\r\n", 1)[1]) >= content_length:
                break
    sock.close()
    return data


def _parse_status(response: bytes) -> int:
    line = response.split(b"\r\n", 1)[0]
    try:
        return int(line.split(b" ", 2)[1])
    except Exception:
        return 0


def _open_https_tunnel(
    proxy_host: str,
    proxy_port: int,
    connect_host: str,
    connect_port: int,
    ca_cert: Path,
    server_hostname: str,
    alpn_protocols: Optional[List[str]] = None,
) -> ssl.SSLSocket:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
    connect_req = f"CONNECT {connect_host}:{connect_port} HTTP/1.1\r\nHost: {connect_host}:{connect_port}\r\n\r\n"
    sock.sendall(connect_req.encode("ascii"))
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if b"200" not in data.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"CONNECT failed: {data!r}")
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    if alpn_protocols:
        ctx.set_alpn_protocols(alpn_protocols)
    tls_sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
    return tls_sock


def _h11_request(
    conn: h11.Connection,
    sock: ssl.SSLSocket,
    method: str,
    target: str,
    body: bytes = b"",
    headers: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[int, bytes]:
    req_headers = headers[:] if headers else []
    if not any(name.lower() == "host" for name, _ in req_headers):
        req_headers.append(("Host", "localhost"))
    if body and not any(name.lower() == "content-length" for name, _ in req_headers):
        req_headers.append(("Content-Length", str(len(body))))
    sock.sendall(conn.send(h11.Request(method=method, target=target, headers=req_headers)))
    if body:
        sock.sendall(conn.send(h11.Data(data=body)))
    sock.sendall(conn.send(h11.EndOfMessage()))
    status = 0
    resp_body = bytearray()
    while True:
        data = sock.recv(4096)
        if not data:
            break
        conn.receive_data(data)
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                break
            if isinstance(event, h11.Response):
                status = event.status_code
            elif isinstance(event, h11.Data):
                resp_body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                if conn.our_state == h11.DONE and conn.their_state == h11.DONE:
                    conn.start_next_cycle()
                return status, bytes(resp_body)
    return status, bytes(resp_body)


def _h11_request_with_headers(
    conn: h11.Connection,
    sock: ssl.SSLSocket,
    method: str,
    target: str,
    body: bytes = b"",
    headers: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[int, bytes, List[Tuple[str, str]]]:
    req_headers = headers[:] if headers else []
    if not any(name.lower() == "host" for name, _ in req_headers):
        req_headers.append(("Host", "localhost"))
    if body and not any(name.lower() == "content-length" for name, _ in req_headers):
        req_headers.append(("Content-Length", str(len(body))))
    sock.sendall(conn.send(h11.Request(method=method, target=target, headers=req_headers)))
    if body:
        sock.sendall(conn.send(h11.Data(data=body)))
    sock.sendall(conn.send(h11.EndOfMessage()))
    status = 0
    resp_body = bytearray()
    resp_headers: List[Tuple[str, str]] = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        conn.receive_data(data)
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                break
            if isinstance(event, h11.Response):
                status = event.status_code
                resp_headers = [(k.decode("ascii", "ignore"), v.decode("ascii", "ignore")) for k, v in event.headers]
            elif isinstance(event, h11.Data):
                resp_body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                if conn.our_state == h11.DONE and conn.their_state == h11.DONE:
                    conn.start_next_cycle()
                return status, bytes(resp_body), resp_headers
    return status, bytes(resp_body), resp_headers


class UpstreamTlsThread:
    def __init__(self, keep_alive: bool = False) -> None:
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[asyncio.base_events.Server] = None
        self._serve_task: Optional[asyncio.Task] = None
        self._started = threading.Event()
        self._bound: Optional[Tuple[str, int]] = None
        self._ca = trustme.CA()
        self._cert = self._ca.issue_cert("localhost")
        self._keep_alive = keep_alive
        self._sequence = 0

    @property
    def ca(self) -> trustme.CA:
        return self._ca

    def start(self) -> Tuple[str, int]:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)
        if not self._bound:
            raise RuntimeError("upstream tls failed to start")
        return self._bound

    def stop(self) -> None:
        if not self._loop or not self._server or not self._thread or not self._thread.is_alive():
            return

        loop = self._loop
        server = self._server
        if loop.is_closed():
            return

        async def _shutdown() -> None:
            server.close()
            await server.wait_closed()
            if self._serve_task and not self._serve_task.done():
                self._serve_task.cancel()
            current = asyncio.current_task(loop=loop)
            pending = [task for task in asyncio.all_tasks(loop) if not task.done() and task is not current]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=2)
            loop.stop()

        fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
        try:
            fut.result(timeout=5)
        except Exception:
            if not loop.is_closed():
                loop.call_soon_threadsafe(loop.stop)
        self._thread.join(timeout=5)

    async def _handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return
        parts = request_line.decode("ascii", errors="ignore").strip().split(" ", 2)
        if len(parts) != 3:
            writer.close()
            return
        method, path, _version = parts
        headers = await _read_headers(reader)
        body = b""
        length = _header_value(headers, "content-length")
        if length:
            body = await reader.readexactly(int(length))
        if path.startswith("/hello"):
            await _send_content_length(writer, 200, b"hello", close=not self._keep_alive)
        elif path == "/sequence":
            self._sequence += 1
            await _send_content_length(
                writer, 200, f"response-{self._sequence}".encode("ascii"), close=not self._keep_alive
            )
        elif path.startswith("/echo") and method.upper() == "POST":
            await _send_content_length(writer, 200, body, close=not self._keep_alive)
        elif path.startswith("/chunked"):
            await _send_chunked(writer, 200, [b"chunk-one", b"chunk-two"], close=not self._keep_alive)
        else:
            await _send_content_length(writer, 404, b"missing", close=not self._keep_alive)
        writer.close()
        await writer.wait_closed()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def _serve() -> None:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._cert.configure_cert(ssl_ctx)
            self._server = await asyncio.start_server(self._handler, host="127.0.0.1", port=0, ssl=ssl_ctx)
            sock = self._server.sockets[0].getsockname()
            self._bound = (sock[0], sock[1])
            self._started.set()
            await self._server.serve_forever()

        try:
            self._serve_task = loop.create_task(_serve())
            loop.run_forever()
        finally:
            loop.close()


class UpstreamSlowHeadersThread(UpstreamThread):
    async def _handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return
        await asyncio.sleep(0.2)
        await _send_content_length(writer, 200, b"late")
        writer.close()
        await writer.wait_closed()


def test_record_replay_get_content_length(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/hello")
            assert resp.status == 200
            assert data == b"hello"
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/hello")
            assert resp.status == 200
            assert data == b"hello"
        connect.assert_not_called()


def test_http_replay_consumes_matching_interactions_in_order(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    upstream = UpstreamThread()
    host, port = upstream.start()
    sequence_url = f"http://{host}:{port}/sequence"
    other_url = f"http://{host}:{port}/hello"
    try:
        with proxy_context(str(config_path), mode="record") as proxy_address:
            assert _request(*proxy_address, "GET", sequence_url)[1] == b"response-1"
            assert _request(*proxy_address, "GET", other_url)[1] == b"hello"
            assert _request(*proxy_address, "GET", sequence_url)[1] == b"response-2"
    finally:
        upstream.stop()
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    recorded = cassette_path.read_bytes()
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as proxy_address:
            assert _request(*proxy_address, "GET", sequence_url)[1] == b"response-1"
            assert _request(*proxy_address, "GET", other_url)[1] == b"hello"
            assert _request(*proxy_address, "GET", sequence_url)[1] == b"response-2"
            miss, body = _request(*proxy_address, "GET", sequence_url)
            assert miss.status == 502 and b"no matching interaction" in body
        connect.assert_not_called()
    assert cassette_path.read_bytes() == recorded


def test_record_replay_post_content_length(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    body = b"ping"
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "POST",
                f"http://{up_host}:{up_port}/echo",
                body=body,
                headers={"Content-Type": "text/plain"},
            )
            assert resp.status == 200
            assert data == body
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(
            proxy_host,
            proxy_port,
            "POST",
            f"http://{up_host}:{up_port}/echo",
            body=body,
            headers={"Content-Type": "text/plain"},
        )
        assert resp.status == 200
        assert data == body


def test_record_replay_chunked_response_replayed_as_content_length(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/chunked")
            assert resp.status == 200
            assert resp.getheader("transfer-encoding") == "chunked"
            assert data == b"chunk-onechunk-two"
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/chunked")
        assert resp.status == 200
        assert resp.getheader("transfer-encoding") is None
        assert resp.getheader("content-length") == str(len(data))


def test_strict_miss_returns_error(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, _data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/hello")
            assert resp.status == 200
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/missing")
            assert resp.status == 502
            assert b"no matching interaction" in data
        connect.assert_not_called()


def test_redaction_headers(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, _data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/sensitive-headers",
                headers={
                    "Authorization": "Bearer synthetic-auth",
                    "Cookie": "session=synthetic-cookie",
                    "X-API-Key": "synthetic-key",
                },
            )
            assert resp.status == 200
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    payload = json.loads(cassette_path.read_text(encoding="utf-8"))
    headers = payload["interactions"][0]["request"]["headers"]
    response_headers = payload["interactions"][0]["response"]["headers"]
    assert headers["authorization"] == [REDACTION_MARKER]
    assert headers["cookie"] == [REDACTION_MARKER]
    assert headers["x-api-key"] == [REDACTION_MARKER]
    assert response_headers["set-cookie"] == [REDACTION_MARKER]
    assert response_headers["x-api-key"] == [REDACTION_MARKER]
    assert "synthetic-auth" not in cassette_path.read_text(encoding="utf-8")
    assert "synthetic-cookie" not in cassette_path.read_text(encoding="utf-8")
    assert "synthetic-key" not in cassette_path.read_text(encoding="utf-8")


def test_url_redaction_preserves_structure() -> None:
    url = (
        "https://example.test/path?keep=one&ToKeN=synthetic-one&keep=two&ACCESS_TOKEN=synthetic-two"
        "&api-key=synthetic-three&empty=&flag&%70assword=synthetic-four&key=synthetic-five#part"
    )
    redacted = redact_url(url)
    assert urlsplit(redacted).path == "/path"
    assert urlsplit(redacted).fragment == "part"
    assert parse_qsl(urlsplit(redacted).query, keep_blank_values=True) == [
        ("keep", "one"),
        ("ToKeN", REDACTION_MARKER),
        ("keep", "two"),
        ("ACCESS_TOKEN", REDACTION_MARKER),
        ("api-key", REDACTION_MARKER),
        ("empty", ""),
        ("flag", ""),
        ("password", REDACTION_MARKER),
        ("key", REDACTION_MARKER),
    ]
    assert "synthetic-" not in redacted
    assert redact_url(redacted) == redacted


def test_common_sensitive_query_key_variants() -> None:
    for name in (
        "token",
        "access_token",
        "refresh-token",
        "api_key",
        "apikey",
        "key",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "auth",
        "authorization",
    ):
        assert redact_url(f"http://example.test/?{name}=synthetic-value") == (
            f"http://example.test/?{name}={REDACTION_MARKER}"
        )
    assert redact_url("http://example.test/?nonce=synthetic-random-looking") == (
        "http://example.test/?nonce=synthetic-random-looking"
    )


def test_url_userinfo_redaction() -> None:
    for original, expected in [
        (
            "https://synthetic-user:synthetic-pass@example.test:8443/path?token=synthetic-token&keep=yes#part",
            "https://***:***@example.test:8443/path?token=***&keep=yes#part",
        ),
        ("https://synthetic-user@example.test/path", "https://***@example.test/path"),
        ("https://synthetic%40user:synthetic%3Apass@example.test/path", "https://***:***@example.test/path"),
        ("https://example.test/path?keep=yes#part", "https://example.test/path?keep=yes#part"),
    ]:
        assert redact_url(original) == expected
        assert redact_url(expected) == expected


def test_recorded_url_is_redacted_but_upstream_receives_original(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    query = "keep=one&token=synthetic-one&keep=two&API_KEY=synthetic-two"
    upstream = UpstreamThread()
    up_host, up_port = upstream.start()
    try:
        url = f"http://synthetic-user:synthetic-pass@{up_host}:{up_port}/hello?{query}"
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "GET",
                url,
                headers={"Authorization": "Basic synthetic-authorization"},
            )
            assert resp.status == 200 and data == b"hello"
        assert upstream.last_path == f"/hello?{query}"
        assert ("Authorization", "Basic synthetic-authorization") in upstream.last_headers
        assert ("Host", f"synthetic-user:synthetic-pass@{up_host}:{up_port}") in upstream.last_headers
    finally:
        upstream.stop()
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    request_record = json.loads(cassette_path.read_text(encoding="utf-8"))["interactions"][0]["request"]
    stored = request_record["url"]
    assert stored == f"http://***:***@{up_host}:{up_port}/hello?keep=one&token=***&keep=two&API_KEY=***"
    assert request_record["headers"]["host"] == [f"***:***@{up_host}:{up_port}"]
    assert "synthetic-" not in cassette_path.read_text(encoding="utf-8")
    cfg = load_config(str(config_path))
    assert verify_cassette(cassette_path, cfg.redaction["headers"], 1, cfg.redaction["body_patterns"]) == []
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "GET",
                url,
                headers={"Authorization": "Basic synthetic-authorization"},
            )
            assert resp.status == 200 and data == b"hello"
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://synthetic-other:synthetic-other@{up_host}:{up_port}/hello?keep=one&token=synthetic-other&keep=two&API_KEY=synthetic-other",
                headers={"Authorization": "Basic synthetic-other"},
            )
            assert resp.status == 200 and data == b"hello"
            resp, data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://synthetic-other:synthetic-other@{up_host}:{up_port}/hello?keep=changed&token=synthetic-other&keep=two&API_KEY=synthetic-other",
                headers={"Authorization": "Basic synthetic-other"},
            )
            assert resp.status == 502 and b"no matching interaction" in data
        connect.assert_not_called()


def test_http_redaction_preserves_binary_bytes(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    body = b"\xff\xfe\x00secret"
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "POST",
                f"http://{up_host}:{up_port}/echo",
                body=body,
            )
            assert resp.status == 200
            assert data == body
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    payload = json.loads(cassette_path.read_text(encoding="utf-8"))
    req_body = base64.b64decode(payload["interactions"][0]["request"]["body_b64"])
    resp_body = base64.b64decode(payload["interactions"][0]["response"]["body_b64"])
    assert b"\xff\xfe\x00" in req_body
    assert b"\xff\xfe\x00" in resp_body
    assert b"secret" not in req_body
    assert b"secret" not in resp_body


def test_https_record_replay_get(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread()
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            client_ctx = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
            conn = http.client.HTTPSConnection(proxy_host, proxy_port, context=client_ctx, timeout=5)
            conn.set_tunnel("localhost", port)
            conn.request("GET", "/hello?access_token=synthetic-https&keep=yes")
            resp = conn.getresponse()
            data = resp.read()
            conn.close()
            assert resp.status == 200
            assert data == b"hello"
    finally:
        upstream.stop()
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    stored_url = json.loads(cassette_path.read_text(encoding="utf-8"))["interactions"][0]["request"]["url"]
    assert stored_url.endswith("/hello?access_token=***&keep=yes")
    assert "synthetic-https" not in cassette_path.read_text(encoding="utf-8")
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            client_ctx = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
            conn = http.client.HTTPSConnection(proxy_host, proxy_port, context=client_ctx, timeout=5)
            conn.set_tunnel("localhost", port)
            conn.request("GET", "/hello?access_token=synthetic-https&keep=yes")
            resp = conn.getresponse()
            data = resp.read()
            conn.close()
            assert resp.status == 200
            assert data == b"hello"
            miss = http.client.HTTPSConnection(proxy_host, proxy_port, context=client_ctx, timeout=5)
            miss.set_tunnel("localhost", port)
            miss.request("GET", "/missing")
            miss_response = miss.getresponse()
            assert miss_response.status == 502
            assert b"no matching interaction" in miss_response.read()
            miss.close()
        connect.assert_not_called()


def test_https_replay_consumes_matching_interactions_in_order(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    client_ctx = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    upstream = UpstreamTlsThread()
    _host, port = upstream.start()

    def request(proxy_host: str, proxy_port: int) -> Tuple[int, bytes]:
        conn = http.client.HTTPSConnection(proxy_host, proxy_port, context=client_ctx, timeout=5)
        conn.set_tunnel("localhost", port)
        conn.request("GET", "/sequence")
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    try:
        with proxy_context(str(config_path), mode="record") as proxy_address:
            assert request(*proxy_address) == (200, b"response-1")
            assert request(*proxy_address) == (200, b"response-2")
    finally:
        upstream.stop()
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    recorded = cassette_path.read_bytes()
    with patch(
        "vcr_proxy.proxy.asyncio.open_connection", side_effect=AssertionError("replay contacted upstream")
    ) as connect:
        with proxy_context(str(config_path), mode="replay") as proxy_address:
            assert request(*proxy_address) == (200, b"response-1")
            assert request(*proxy_address) == (200, b"response-2")
            status, body = request(*proxy_address)
            assert status == 502 and b"no matching interaction" in body
        connect.assert_not_called()
    assert cassette_path.read_bytes() == recorded


def test_https_alpn_forces_http1(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread()
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="localhost",
                alpn_protocols=["h2", "http/1.1"],
            )
            assert tls_sock.selected_alpn_protocol() == "http/1.1"
            conn = h11.Connection(h11.CLIENT)
            status, body = _h11_request(conn, tls_sock, "GET", "/hello")
            tls_sock.close()
            assert status == 200
            assert body == b"hello"
    finally:
        upstream.stop()


def test_https_sni_uses_certificate_for_sni(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread()
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="sni.test",
            )
            cert = tls_sock.getpeercert()
            sans = cert.get("subjectAltName", [])
            assert ("DNS", "sni.test") in sans
            conn = h11.Connection(h11.CLIENT)
            status, body = _h11_request(conn, tls_sock, "GET", "/hello")
            tls_sock.close()
            assert status == 200
            assert body == b"hello"
    finally:
        upstream.stop()


def test_https_redaction_headers_and_body(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread()
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="localhost",
            )
            conn = h11.Connection(h11.CLIENT)
            headers = [("Authorization", "Bearer secret")]
            body = b"secret payload"
            status, data = _h11_request(conn, tls_sock, "POST", "/echo", body=body, headers=headers)
            assert status == 200
            assert data == body
            tls_sock.close()
        cassette_path = tmp_path / "cassettes" / "cassette.json"
        payload = json.loads(cassette_path.read_text(encoding="utf-8"))
        req_headers = payload["interactions"][0]["request"]["headers"]
        req_body = base64.b64decode(payload["interactions"][0]["request"]["body_b64"])
        resp_body = base64.b64decode(payload["interactions"][0]["response"]["body_b64"])
        assert req_headers["authorization"] == ["***"]
        assert b"secret" not in req_body
        assert b"secret" not in resp_body
    finally:
        upstream.stop()


def test_https_keepalive_multiple_requests(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread(keep_alive=True)
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="localhost",
            )
            conn = h11.Connection(h11.CLIENT)
            status, body = _h11_request(conn, tls_sock, "GET", "/hello")
            assert status == 200
            assert body == b"hello"
            big_body = b"a" * 200000
            status, body = _h11_request(conn, tls_sock, "POST", "/echo", body=big_body)
            assert status == 200
            assert body == big_body
            tls_sock.close()
    finally:
        upstream.stop()


def test_http_ignore_query_params(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, match_overrides={"ignore_query_params": ["b"]})
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/hello?a=1&b=2",
            )
            assert resp.status == 200
            assert data == b"hello"
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(
            proxy_host,
            proxy_port,
            "GET",
            f"http://{up_host}:{up_port}/hello?a=1&b=999",
        )
        assert resp.status == 200
        assert data == b"hello"


def test_http_headers_allowlist(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, match_overrides={"headers_allowlist": ["x-match"]})
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, _data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/hello",
                headers={"X-Match": "a", "X-Other": "1"},
            )
            assert resp.status == 200
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(
            proxy_host,
            proxy_port,
            "GET",
            f"http://{up_host}:{up_port}/hello",
            headers={"X-Match": "a", "X-Other": "2", "Connection": "close"},
        )
        assert resp.status == 200
        assert data == b"hello"


def test_http_headers_denylist(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, match_overrides={"headers_denylist": ["x-ignore"]})
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, _data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/hello",
                headers={"X-Ignore": "a"},
            )
            assert resp.status == 200
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(
            proxy_host,
            proxy_port,
            "GET",
            f"http://{up_host}:{up_port}/hello",
            headers={"X-Ignore": "b"},
        )
        assert resp.status == 200
        assert data == b"hello"


def test_http_body_strategy_exact(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, match_overrides={"body": {"strategy": "exact"}})
    with upstream_context() as (up_host, up_port):
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(
                proxy_host,
                proxy_port,
                "POST",
                f"http://{up_host}:{up_port}/echo",
                body=b"abc",
            )
            assert resp.status == 200
            assert data == b"abc"
    with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
        resp, data = _request(
            proxy_host,
            proxy_port,
            "POST",
            f"http://{up_host}:{up_port}/echo",
            body=b"abc",
        )
        assert resp.status == 200
        assert data == b"abc"
        resp, data = _request(
            proxy_host,
            proxy_port,
            "POST",
            f"http://{up_host}:{up_port}/echo",
            body=b"abcd",
        )
        assert resp.status == 502
        assert b"no matching interaction" in data


def test_http_forces_connection_close(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    upstream = UpstreamThread(keep_alive=True)
    up_host, up_port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, _data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/hello",
            )
            assert resp.getheader("connection") == "close"
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            resp, _data = _request(
                proxy_host,
                proxy_port,
                "GET",
                f"http://{up_host}:{up_port}/hello",
            )
            assert resp.getheader("connection") == "close"
    finally:
        upstream.stop()


def test_http_proxy_form_required(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        response = _raw_http_request(proxy_host, proxy_port, request)
        assert _parse_status(response) == 400
        assert b"proxy-form url required" in response


def test_https_invalid_connect_target(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    init_ca(tmp_path / "ca" / "ca.key", tmp_path / "ca" / "ca.crt", None)
    with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
        request = b"CONNECT badtarget:bad HTTP/1.1\r\nHost: badtarget:bad\r\n\r\n"
        response = _raw_http_request(proxy_host, proxy_port, request)
        assert _parse_status(response) == 400


def test_https_disabled_rejects_connect(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
        request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        response = _raw_http_request(proxy_host, proxy_port, request)
        assert _parse_status(response) == 400
        assert b"https not enabled" in response


def test_http_upstream_connection_refused(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
        resp, _data = _request(proxy_host, proxy_port, "GET", "http://127.0.0.1:1/hello")
        assert resp.status == 400


def test_http_upstream_response_timeout_returns_gateway_timeout(tmp_path: Path) -> None:
    config_path = _write_config_with_limits(tmp_path, upstream_timeout_ms=50)
    upstream = UpstreamSlowHeadersThread()
    up_host, up_port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            resp, data = _request(proxy_host, proxy_port, "GET", f"http://{up_host}:{up_port}/hello")
            assert resp.status == 504
            assert b"upstream timed out" in data
    finally:
        upstream.stop()


def test_load_config_missing_tls_defaults_disabled(tmp_path: Path) -> None:
    config = {
        "listen": {"host": "127.0.0.1", "port": 0},
        "cassette_dir": str(tmp_path / "cassettes"),
        "limits": {"upstream_timeout_ms": 30000},
        "match": {
            "method": True,
            "url": True,
            "ignore_query_params": [],
            "headers_allowlist": [],
            "headers_denylist": [],
            "body": {"strategy": "hash"},
        },
        "redaction": {
            "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
            "body_patterns": [{"pattern": "secret", "replacement": "***"}],
        },
        "cassette": {"file_strategy": "single", "schema_version": 1},
    }
    path = tmp_path / ".vcr-proxy.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cfg = load_config(str(path))
    assert cfg.tls["enabled"] is False


def test_load_config_partial_tls_uses_defaults(tmp_path: Path) -> None:
    config = {
        "listen": {"host": "127.0.0.1", "port": 0},
        "cassette_dir": str(tmp_path / "cassettes"),
        "limits": {"upstream_timeout_ms": 30000},
        "match": {
            "method": True,
            "url": True,
            "ignore_query_params": [],
            "headers_allowlist": [],
            "headers_denylist": [],
            "body": {"strategy": "hash"},
        },
        "redaction": {
            "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
            "body_patterns": [{"pattern": "secret", "replacement": "***"}],
        },
        "cassette": {"file_strategy": "single", "schema_version": 1},
        "tls": {"enabled": True},
    }
    path = tmp_path / ".vcr-proxy.json"
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cfg = load_config(str(path))
    assert cfg.tls["enabled"] is True
    assert cfg.tls["ca_dir"] == "ca"
    assert cfg.tls["ca_key"] == "ca.key"
    assert cfg.tls["ca_cert"] == "ca.crt"
    assert cfg.tls["leaf_dir"] == "ca/leaf"


def test_verify_schema_and_redaction_errors(tmp_path: Path) -> None:
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"schema_version": 1, "interactions": [{}]}), encoding="utf-8")
    errors = verify_cassette(bad_path, ["authorization"], 1)
    assert errors
    redacted = tmp_path / "redacted.json"
    redacted.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://example.com",
                            "headers": {"authorization": ["secret"]},
                            "body_b64": "",
                            "body_sha256": "",
                            "truncated": False,
                        },
                        "response": {
                            "status": 200,
                            "reason": "OK",
                            "headers": {},
                            "body_b64": "",
                            "body_sha256": "",
                            "truncated": False,
                        },
                        "timing": {"started_at": 0, "duration_ms": 1},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    errors = verify_cassette(redacted, ["authorization"], 1)
    assert errors


def test_verify_detects_exposure_on_each_stored_surface(tmp_path: Path) -> None:
    baseline = {
        "schema_version": 1,
        "interactions": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://***:***@example.test/path?token=***&keep=yes",
                    "headers": {
                        "authorization": ["***"],
                        "cookie": ["***"],
                        "x-api-key": ["***"],
                        "host": ["***:***@example.test"],
                    },
                    "body_b64": base64.b64encode(b"safe request").decode("ascii"),
                    "body_sha256": "synthetic-hash",
                    "truncated": False,
                },
                "response": {
                    "status": 200,
                    "reason": "OK",
                    "headers": {"set-cookie": ["***"]},
                    "body_b64": base64.b64encode(b"safe response").decode("ascii"),
                    "body_sha256": "synthetic-hash",
                    "truncated": False,
                },
                "timing": {"started_at": 0, "duration_ms": 1},
            }
        ],
    }
    patterns = [{"pattern": "synthetic-secret", "replacement": "***"}]
    path = tmp_path / "cassette.json"

    def check(payload: Any, expected: str) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")
        errors = verify_cassette(path, ["authorization", "cookie", "set-cookie", "x-api-key"], 1, patterns)
        assert any(expected in error for error in errors), errors

    path.write_text(json.dumps(baseline), encoding="utf-8")
    assert verify_cassette(path, ["authorization", "cookie", "set-cookie", "x-api-key"], 1, patterns) == []

    for side, field, value, expected in [
        ("request", "url", "https://example.test/path?token=synthetic-secret", "url query parameter"),
        ("request", "url", "https://synthetic-user:synthetic-secret@example.test/path", "url contains userinfo"),
        ("request", "url", "https://synthetic-user@example.test/path", "url contains userinfo"),
        ("request", "headers", {"authorization": ["synthetic-secret"]}, "header not redacted"),
        ("request", "headers", {"cookie": ["synthetic-secret"]}, "header not redacted"),
        ("request", "headers", {"x-api-key": ["synthetic-secret"]}, "header not redacted"),
        (
            "request",
            "headers",
            {"host": ["synthetic-user:synthetic-secret@example.test"]},
            "header contains unredacted userinfo",
        ),
        ("request", "headers", {"host": ["synthetic-user@[bad"]}, "header invalid"),
        ("response", "headers", {"set-cookie": ["synthetic-secret"]}, "header not redacted"),
        ("request", "body_b64", base64.b64encode(b"synthetic-secret").decode("ascii"), "request body contains"),
        ("response", "body_b64", base64.b64encode(b"synthetic-secret").decode("ascii"), "response body contains"),
    ]:
        payload = json.loads(json.dumps(baseline))
        payload["interactions"][0][side][field] = value
        check(payload, expected)


def test_verify_reports_malformed_cassettes(tmp_path: Path) -> None:
    path = tmp_path / "cassette.json"
    for payload, expected in [
        ([], "root is not an object"),
        ({"schema_version": 1, "interactions": [None]}, "interaction 0 is not an object"),
        (
            {"schema_version": 1, "interactions": [{"request": [], "response": {}, "timing": {}}]},
            "request is not an object",
        ),
        (
            {
                "schema_version": 1,
                "interactions": [
                    {"request": {"url": 42, "headers": {}, "body_b64": "not base64"}, "response": {}, "timing": {}}
                ],
            },
            "body_b64 invalid",
        ),
    ]:
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert any(expected in error for error in verify_cassette(path, [], 1))


def test_concurrent_appends_keep_every_interaction(tmp_path: Path) -> None:
    cfg = load_config(str(_write_config(tmp_path)))
    cassette_path = cfg.cassette_dir / "cassette.json"
    start = threading.Barrier(8)

    def record(worker: int) -> None:
        start.wait()
        for offset in range(8):
            index = worker * 8 + offset
            interaction = {
                "request": {
                    "method": "GET",
                    "url": f"http://example.test/{index}",
                    "headers": {},
                    "body_b64": "",
                    "body_sha256": "",
                    "truncated": False,
                },
                "response": {
                    "status": 200,
                    "reason": "OK",
                    "headers": {},
                    "body_b64": "",
                    "body_sha256": "",
                    "truncated": False,
                },
                "timing": {"started_at": 0, "duration_ms": 0},
            }
            cassette_io.append_interaction(cassette_path, cfg, interaction)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(8)))
    interactions = cassette_io.load_cassette(cassette_path)["interactions"]
    assert len(interactions) == 64
    assert {item["request"]["url"] for item in interactions} == {f"http://example.test/{index}" for index in range(64)}


def test_atomic_write_preserves_previous_cassette_on_failure(tmp_path: Path) -> None:
    path = tmp_path / "cassette.json"
    cassette_io.write_cassette(path, {"schema_version": 1, "interactions": []})
    original = path.read_bytes()
    with patch("vcr_proxy.cassette.os.replace", side_effect=OSError("synthetic failure")):
        with pytest.raises(cassette_io.CassetteWriteError, match="could not write cassette"):
            cassette_io.write_cassette(path, {"schema_version": 1, "interactions": [{"new": True}]})
    assert path.read_bytes() == original
    assert list(tmp_path.glob(".cassette.json.*.tmp")) == []


def test_record_write_failure_is_logged_without_request_data(tmp_path: Path, caplog) -> None:
    config_path = _write_config(tmp_path)
    with upstream_context() as (host, port):
        with patch(
            "vcr_proxy.proxy.cassette_io.append_interaction",
            side_effect=cassette_io.CassetteWriteError("could not write cassette"),
        ):
            with proxy_context(str(config_path), mode="record") as proxy_address:
                response, body = _request(*proxy_address, "GET", f"http://{host}:{port}/hello?token=synthetic-secret")
                assert response.status == 200 and body == b"hello"
    assert "cassette recording failed: could not write cassette" in caplog.text
    assert "synthetic-secret" not in caplog.text


def test_malformed_replay_cassette_returns_clear_error(tmp_path: Path, caplog) -> None:
    config_path = _write_config(tmp_path)
    cassette_path = tmp_path / "cassettes" / "cassette.json"
    cassette_path.parent.mkdir()
    url = "http://127.0.0.1:12345/private?token=synthetic-secret"
    with proxy_context(str(config_path), mode="replay") as proxy_address:
        for content in (
            "not json",
            json.dumps({"schema_version": 1, "interactions": [{"request": {}, "response": {}}]}),
        ):
            cassette_path.write_text(content, encoding="utf-8")
            response, body = _request(*proxy_address, "GET", url)
            assert response.status == 502 and body == b"invalid cassette"
    assert "cassette replay failed" in caplog.text
    assert "synthetic-secret" not in caplog.text


def test_proxy_context_restores_existing_proxy_environment(monkeypatch) -> None:
    names = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    original = {name: f"http://previous-{name.lower()}" for name in names}
    for name, value in original.items():
        monkeypatch.setenv(name, value)
    with patch("vcr_proxy.pytest_helper.ProxyThread") as thread:
        thread.return_value.start.return_value = ("127.0.0.1", 4321)
        with proxy_context("unused") as address:
            assert address == ("127.0.0.1", 4321)
            assert {name: os.environ[name] for name in names} == {name: "http://127.0.0.1:4321" for name in names}
        thread.return_value.stop.assert_called_once_with()
    assert {name: os.environ[name] for name in names} == original


def test_proxy_context_removes_previously_absent_proxy_environment(monkeypatch) -> None:
    names = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    for name in names:
        monkeypatch.delenv(name, raising=False)
    with patch("vcr_proxy.pytest_helper.ProxyThread") as thread:
        thread.return_value.start.return_value = ("127.0.0.1", 4321)
        with proxy_context("unused"):
            assert all(os.environ[name] == "http://127.0.0.1:4321" for name in names)
        thread.return_value.stop.assert_called_once_with()
    assert all(name not in os.environ for name in names)


def test_doctor_output(capsys) -> None:
    from vcr_proxy.cli import _doctor

    _doctor()
    out = capsys.readouterr().out
    assert "HTTP_PROXY" in out


def test_https_chunked_response_replayed_as_content_length(tmp_path: Path) -> None:
    config_path = _write_tls_config(tmp_path)
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir / "ca.key", ca_dir / "ca.crt", None)
    upstream = UpstreamTlsThread()
    host, port = upstream.start()
    try:
        with proxy_context(str(config_path), mode="record") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="localhost",
            )
            conn = h11.Connection(h11.CLIENT)
            status, body, headers = _h11_request_with_headers(conn, tls_sock, "GET", "/chunked")
            tls_sock.close()
            assert status == 200
            assert body == b"chunk-onechunk-two"
            assert any(name.lower() == "transfer-encoding" for name, _ in headers)
        with proxy_context(str(config_path), mode="replay") as (proxy_host, proxy_port):
            tls_sock = _open_https_tunnel(
                proxy_host,
                proxy_port,
                "localhost",
                port,
                ca_dir / "ca.crt",
                server_hostname="localhost",
            )
            conn = h11.Connection(h11.CLIENT)
            status, body, headers = _h11_request_with_headers(conn, tls_sock, "GET", "/chunked")
            tls_sock.close()
            assert status == 200
            assert body == b"chunk-onechunk-two"
            assert not any(name.lower() == "transfer-encoding" for name, _ in headers)
            assert any(name.lower() == "content-length" for name, _ in headers)
    finally:
        upstream.stop()
