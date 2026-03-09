import asyncio
import os
import threading
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple

from .config import load_config
from .proxy import ProxyServer


class ProxyThread:
    def __init__(self, config_path: str, mode: str) -> None:
        self.config_path = config_path
        self.mode = mode
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[ProxyServer] = None
        self._serve_task: Optional[asyncio.Task] = None
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._bound: Optional[Tuple[str, int]] = None

    def start(self) -> Tuple[str, int]:
        if self._thread:
            raise RuntimeError("proxy already started")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)
        if not self._bound:
            raise RuntimeError("proxy failed to start")
        return self._bound

    def stop(self) -> None:
        if not self._loop or not self._server or not self._thread or not self._thread.is_alive():
            return
        loop = self._loop
        server = self._server
        if loop.is_closed():
            return

        async def _shutdown() -> None:
            await server.stop()
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

    def _run(self) -> None:
        cfg = load_config(self.config_path)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = ProxyServer(cfg, self.mode)
        self._loop = loop
        self._server = server

        async def _serve() -> None:
            await server.start()
            self._bound = server.bound_address
            self._started.set()
            await server.serve_forever()

        try:
            self._serve_task = loop.create_task(_serve())
            loop.run_forever()
        finally:
            loop.close()
            self._stopped.set()


@contextmanager
def proxy_context(config_path: str, mode: str = "record") -> Iterator[Tuple[str, int]]:
    proxy = ProxyThread(config_path, mode)
    previous_http = os.environ.get("HTTP_PROXY")
    previous_lower = os.environ.get("http_proxy")
    host, port = proxy.start()
    proxy_url = f"http://{host}:{port}"
    os.environ["HTTP_PROXY"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    try:
        yield host, port
    finally:
        if previous_http is None:
            os.environ.pop("HTTP_PROXY", None)
        else:
            os.environ["HTTP_PROXY"] = previous_http
        if previous_lower is None:
            os.environ.pop("http_proxy", None)
        else:
            os.environ["http_proxy"] = previous_lower
        proxy.stop()
