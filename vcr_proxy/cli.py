import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import List

from .config import config_errors, default_config_dict, load_config
from .proxy import ProxyServer
from .verify import verify_cassette


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="vcr-proxy")
    sub = parser.add_subparsers(dest="command", required=True)

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--config", required=False, default=".vcr-proxy.json")

    record = sub.add_parser("record", parents=[base], help="Record HTTP interactions")
    replay = sub.add_parser("replay", parents=[base], help="Replay HTTP interactions")
    verify = sub.add_parser("verify", parents=[base], help="Verify cassette files")
    sub.add_parser("doctor", help="Print setup hints")
    init = sub.add_parser("init", parents=[base], help="Write a default config file")
    ca_init = sub.add_parser("ca-init", parents=[base], help="Create a local CA for HTTPS MITM")

    record.set_defaults(mode="record")
    replay.set_defaults(mode="replay")
    verify.set_defaults(mode="verify")
    ca_init.set_defaults(mode="ca-init")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.command == "doctor":
        return _doctor()
    if args.command == "init":
        return _write_default_config(args.config)
    if args.command == "ca-init":
        return _ca_init(args.config)
    if args.command == "verify":
        return _verify(args.config)
    cfg = load_config(args.config)
    server = ProxyServer(cfg, args.mode)
    print(f"vcr-proxy {args.mode} listening on {cfg.listen_host}:{cfg.listen_port}")
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        return 0
    return 0


def _verify(config_path: str) -> int:
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    errors = config_errors(raw)
    if errors:
        for err in errors:
            print(f"config: {err}")
        return 2
    cfg = load_config(config_path)
    cassette_dir = cfg.cassette_dir
    errors = _verify_cassettes(
        cassette_dir, cfg.redaction.get("headers", []), cfg.cassette["schema_version"],
        cfg.redaction.get("body_patterns", []),
    )
    if errors:
        for err in errors:
            print(err)
        return 2
    print("ok")
    return 0


def _verify_cassettes(
    cassette_dir: Path, redact_headers: List[str], schema_version: int,
    body_patterns: List[dict],
) -> List[str]:
    errors: List[str] = []
    if not cassette_dir.exists():
        return [f"{cassette_dir}: not found"]
    for path in cassette_dir.glob("*.json"):
        errors.extend(verify_cassette(path, redact_headers, schema_version, body_patterns))
    return errors


def _doctor() -> int:
    host = os.environ.get("VCR_PROXY_HOST", "127.0.0.1")
    port = os.environ.get("VCR_PROXY_PORT", "8080")
    print("vcr-proxy doctor")
    print(f"HTTP_PROXY=http://{host}:{port}")
    print("For HTTPS, use CONNECT via your client's proxy settings.")
    print("Run `vcr-proxy ca-init` and trust the CA for MITM.")
    print("Chunked request bodies are not supported in the MVP.")
    print("Proxy-form requests (absolute URLs) are required.")
    return 0


def _write_default_config(path: str) -> int:
    target = Path(path)
    if target.exists():
        print(f"{path} already exists")
        return 1
    data = default_config_dict()
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path}")
    return 0


def _ca_init(config_path: str) -> int:
    from .tls_ca import init_ca

    cfg = load_config(config_path)
    tls = cfg.tls
    ca_dir = Path(tls["ca_dir"])
    key_path = ca_dir / tls["ca_key"]
    cert_path = ca_dir / tls["ca_cert"]
    try:
        init_ca(key_path, cert_path, tls.get("key_password"))
    except FileExistsError:
        print("CA already exists")
        return 1
    print(f"wrote {key_path}")
    print(f"wrote {cert_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
