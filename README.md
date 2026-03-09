# VCR Proxy (HTTP + HTTPS MITM)

Record and replay HTTP/1.1 interactions for deterministic tests. Asyncio + stdlib for core I/O, with TLS MITM for HTTPS.

## Quick start (Windows)

```bat
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Create a default config:

```bat
python -m vcr_proxy.cli init --config .vcr-proxy.json
```

Create a local CA for HTTPS MITM (once per machine or repo):

```bat
python -m vcr_proxy.cli ca-init --config .vcr-proxy.json
```

Trust the CA in Windows (Current User store):

```bat
certutil -user -addstore "Root" ca\ca.crt
```

Run record mode:

```bat
python -m vcr_proxy.cli record --config .vcr-proxy.json
```

Point your client to the proxy:

```bat
set HTTP_PROXY=http://127.0.0.1:8080
```

Stop the proxy (Ctrl+C), then run replay mode:

```bat
python -m vcr_proxy.cli replay --config .vcr-proxy.json
```

## Quick test with curl (HTTPS)

```bat
curl -v --ssl-no-revoke --cacert ca\ca.crt -H "Connection: close" -x http://127.0.0.1:8080 https://example.com
```

Run once in record mode, then again in replay mode.

Install the package to get the `vcr-proxy` command:

```bat
pip install .
```

For editable development installs with test dependencies:

```bat
pip install -e .[test]
```

## Commands

- `vcr-proxy record --config .vcr-proxy.json`
- `vcr-proxy replay --config .vcr-proxy.json`
- `vcr-proxy verify --config .vcr-proxy.json`
- `vcr-proxy doctor`
- `vcr-proxy init --config .vcr-proxy.json`
- `vcr-proxy ca-init --config .vcr-proxy.json`

If you did not install the CLI, use `python -m vcr_proxy.cli ...` instead.

## Config

Example `.vcr-proxy.json`:

```json
{
  "listen": { "host": "127.0.0.1", "port": 8080 },
  "cassette_dir": "cassettes",
  "limits": { "upstream_timeout_ms": 30000 },
  "match": {
    "method": true,
    "url": true,
    "ignore_query_params": [],
    "headers_allowlist": [],
    "headers_denylist": [],
    "body": { "strategy": "hash" }
  },
  "redaction": {
    "headers": ["authorization", "cookie", "set-cookie", "x-api-key"],
    "body_patterns": [{ "pattern": "Bearer [A-Za-z0-9._-]+", "replacement": "***" }]
  },
  "cassette": { "file_strategy": "single", "schema_version": 1 },
  "tls": {
    "enabled": false,
    "ca_dir": "ca",
    "ca_key": "ca.key",
    "ca_cert": "ca.crt",
    "leaf_dir": "ca/leaf",
    "key_password": null,
    "upstream_insecure": false,
    "upstream_ca_bundle": null
  }
}
```

## HTTPS setup (MITM)

1) Generate the CA with `ca-init` before using HTTPS.
2) Trust the generated `ca.crt` in your client or OS trust store.
3) Use HTTPS as normal through the proxy (client must use CONNECT).

Windows import (Current User):

```bat
certutil -user -addstore "Root" ca\ca.crt
```

To remove later:

```bat
certutil -user -delstore "Root" "vcr-proxy local CA"
```

## Behavior notes

- HTTP and HTTPS via CONNECT are supported.
- Proxy-form requests (absolute URLs) are required for HTTP.
- Replay is strict: no match returns 502.
- Upstream chunked responses are stored dechunked and replayed with `Content-Length`.
- Request and response bodies are stored in full (no truncation).
- Chunked request bodies are not supported in the MVP.
- HTTPS client connections use ALPN `http/1.1` only.

## Cassette format

JSON with sorted keys and stable formatting. Bodies are base64-encoded.

Top-level keys:
- `schema_version`
- `interactions`

Each interaction:
- `request`: `method`, `url`, `headers`, `body_b64`, `body_sha256`, `truncated`
- `response`: `status`, `reason`, `headers`, `body_b64`, `body_sha256`, `truncated`
- `timing`: `started_at`, `duration_ms`

## Verify

```bat
python -m vcr_proxy.cli verify --config .vcr-proxy.json
```

Checks cassette schema and ensures redacted headers are masked.

## Tests

```bat
python -m pytest -q
```

## Pytest helper

Use the helper to run the proxy in tests:

```python
from vcr_proxy.pytest_helper import proxy_context

with proxy_context(".vcr-proxy.json", mode="record") as (host, port):
    ...
```
