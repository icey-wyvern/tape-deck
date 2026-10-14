# Tape Deck

[![CI](https://github.com/icey-wyvern/tape-deck/actions/workflows/ci.yml/badge.svg)](https://github.com/icey-wyvern/tape-deck/actions/workflows/ci.yml)

Tape Deck is a local HTTP/HTTPS record-and-replay proxy for deterministic integration tests. It records real upstream HTTP/1.1 traffic in JSON cassettes, then replays those responses without contacting the upstream service. HTTPS works through interception with a locally generated certificate authority (CA).

The installed command is `vcr-proxy` and the Python package is `vcr_proxy`. The config file remains `.vcr-proxy.json`.

## Request flow

```text
Record: client/test --> Tape Deck --> upstream
                           |
                           +--> JSON cassette

Replay: client/test --> Tape Deck --> JSON cassette
                           X upstream
```

For HTTPS, the client sends `CONNECT` to Tape Deck. Tape Deck presents a leaf certificate signed by its local CA, handles HTTP/1.1 inside the TLS tunnel, and connects to the upstream only while recording.

## Try it

Use Python 3.12+ in an active virtual environment. The recording step needs internet access and `curl`; on Windows PowerShell, use `curl.exe` in place of `curl`. The example's `--ssl-revoke-best-effort` option handles missing revocation status for the local CA with Windows Schannel.

```sh
python -m pip install -e .
vcr-proxy init --config .vcr-proxy.json
python -c "import json, pathlib; p=pathlib.Path('.vcr-proxy.json'); c=json.loads(p.read_text()); c['tls']['enabled']=True; p.write_text(json.dumps(c, indent=2) + '\n')"
vcr-proxy ca-init --config .vcr-proxy.json
```

The generated config starts with HTTPS interception disabled; the third command enables it. `ca-init` writes the local CA under `ca/`. The `--cacert` option below trusts that CA for this request, so system-wide CA installation is unnecessary.

Start recording in one terminal:

```sh
vcr-proxy record --config .vcr-proxy.json
```

In another terminal, make a request through the proxy:

```sh
curl -i --proxy http://127.0.0.1:8080 --noproxy "" --cacert ca/ca.crt --ssl-revoke-best-effort https://example.com/
```

The response should include `HTTP/1.1 200 OK`. Stop record mode with Ctrl+C. You can disconnect from the network now to demonstrate offline replay. Start the proxy again in replay mode, then repeat the same `curl` command:

```sh
vcr-proxy replay --config .vcr-proxy.json
```

The same page body should appear again, including while offline. The cassette is in `cassettes/cassette.json`; `vcr-proxy verify --config .vcr-proxy.json` checks its schema and known/configured redaction surfaces.

## Guarantees and controls

- **Offline replay:** A matching request is served from the cassette. Matching interactions are consumed in recorded order within one proxy run. After they are exhausted, replay returns a 502 miss and never falls back to the upstream. A fresh replay process starts from the first interaction again.
- **Cassette writes:** Recording serializes concurrent appends with an in-process, per-cassette lock and replaces completed JSON files atomically. This does not coordinate separate processes or machines.
- **Credential handling:** Before persistence, Tape Deck masks configured request/response headers and body patterns, common credential-bearing query parameters, and URL userinfo. `verify` checks cassette structure and these known/configured surfaces. Add redaction rules for application-specific sensitive fields; arbitrary secrets cannot always be detected.
- **Configuration:** `cassette_dir` and `cassette.file_strategy` select storage; `match` controls method, URL, headers, and body matching; `redaction` controls headers and body patterns; `tls` controls HTTPS interception and upstream certificate verification. `vcr-proxy init` generates the full default config.

## Limits

Tape Deck handles HTTP/1.1. Plain HTTP clients must send absolute-form proxy requests; HTTPS clients must use `CONNECT`. Chunked request bodies are unsupported. Upstream chunked responses are stored dechunked and replayed with `Content-Length`. Request and response bodies are stored in full where applicable, as base64 in cassettes after configured redaction. Cassette contents can therefore be large or sensitive if redaction is incomplete.

## Development

Install the development extra and run the same gates as [GitHub Actions](.github/workflows/ci.yml):

```sh
python -m pip install -r requirements.txt
ruff format --check
ruff check
mypy vcr_proxy
python -m pytest -q -p no:cacheprovider
```

The `vcr_proxy.pytest_helper.proxy_context` helper starts Tape Deck inside a test and sets both HTTP and HTTPS proxy environment variables for its duration.

Tape Deck is licensed under [Apache-2.0](LICENSE).
