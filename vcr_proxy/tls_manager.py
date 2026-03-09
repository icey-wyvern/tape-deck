import ssl
from pathlib import Path
from typing import Dict, Optional

from .tls_ca import CaBundle, ensure_leaf, load_ca


class TlsManager:
    def __init__(self, ca_key_path: Path, ca_cert_path: Path, leaf_dir: Path, password: Optional[str]) -> None:
        self._ca_key_path = ca_key_path
        self._ca_cert_path = ca_cert_path
        self._leaf_dir = leaf_dir
        self._password = password
        self._ca = load_ca(ca_key_path, ca_cert_path, password)
        self._contexts: Dict[str, ssl.SSLContext] = {}

    def server_context_for_host(self, host: str) -> ssl.SSLContext:
        if host in self._contexts:
            return self._contexts[host]
        cert_path, key_path = ensure_leaf(host, self._ca, self._leaf_dir, self._password)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        if hasattr(ssl, "OP_NO_RENEGOTIATION"):
            ctx.options |= ssl.OP_NO_RENEGOTIATION
        ctx.load_cert_chain(str(cert_path), str(key_path), password=self._password)
        self._contexts[host] = ctx
        return ctx

    def server_context(self, default_host: str) -> ssl.SSLContext:
        ctx = self.server_context_for_host(default_host)

        def _sni_callback(sslobj: ssl.SSLObject, server_name: str, _ctx: ssl.SSLContext) -> None:
            if not server_name:
                return
            try:
                sslobj.context = self.server_context_for_host(server_name)
            except Exception:
                return

        ctx.set_servername_callback(_sni_callback)
        return ctx

    def upstream_context(self, verify: bool, ca_bundle_path: Optional[Path] = None) -> ssl.SSLContext:
        if verify:
            ctx = ssl.create_default_context(cafile=str(ca_bundle_path) if ca_bundle_path else None)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx
