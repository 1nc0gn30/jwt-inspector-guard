<div align="center">
  <img src="assets/hero-banner.svg" alt="JWT Inspector Guard banner" width="100%" />
</div>

# JWT Inspector Guard

[![CI](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-10B981?style=flat-square)](LICENSE)
[![Port](https://img.shields.io/badge/loopback-127.0.0.1%3A8124-38BDF8?style=flat-square)](#port)

Offline JSON Web Token (JWT / JWS) decoder, HMAC signature verifier, claims validator, security linter, RFC 9449 DPoP proof tool, and JWKS rotation simulator. Ships as a Python CLI, a stdio MCP server, a loopback REST API, and a single-file browser workstation. The Python core uses only the standard library.

- Zoth Studio v2 dossier: https://zoth.nullai.tech/tools/jwt-inspector-guard
- Source: https://github.com/1nc0gn30/jwt-inspector-guard

## What It Does

- Decodes compact JWTs into JOSE header, claims payload, and signature, with Base64URL padding normalization.
- Verifies and signs `HS256`, `HS384`, `HS512` using constant-time `hmac.compare_digest` (rejecting `alg: none` by default unless `--allow-none` is explicitly provided), plus pure-Python NIST P-256 ECDSA (`ES256`) and RSA PKCS#1 v1.5 (`RS256`/`RS384`/`RS512`) JWK signature verification.
- Validates RFC 7519 claims (`exp`, `nbf`, `iat`, `iss`, `aud`) with configurable clock-skew leeway.
- Lints tokens for known weaknesses: `alg: none` (CVE-2015-9235, including case variants such as `nOnE`), RSA/HMAC algorithm confusion, header injection (`jku`, `x5u`, `jwk`, `kid` path traversal), weak HMAC secrets (`1,954`-word dictionary), and sensitive data in the payload. Produces a score, grade, and recommendations.
- Creates and cryptographically verifies RFC 9449 ECDSA P-256 (`ES256`) DPoP proofs (`htm`/`htu` binding, `ath` access-token hash, `cnf.jkt` RFC 7638 thumbprint, `jti` replay cache, fail-closed forged-signature rejection).
- Simulates JWKS key lifecycles (`active -> retiring -> revoked`) and audits external JWKS files.
- Empirically benchmarks constant-time vs early-exit signature comparison to measure timing side channels.

All processing happens locally with zero external CDN requests and zero cloud uploads. The dual-theme browser UI performs decoding, auditing, HS/RS/ES JWK verification, and ES256 DPoP signing with Web Crypto and integrates directly with the hardened `127.0.0.1:8124` REST API.

## How It Works

```mermaid
flowchart LR
    CLI["jwt-inspector-guard / jwt-guard"] --> CORE["src/jwt_inspector_guard"]
    MCP["MCP client"] -->|"stdio JSON-RPC 2.0"| MCPSRV["mcp_server.py"]
    UI["public/index.html"] --> HTTP["server.py -> ui_server.py (127.0.0.1:8124)"]
    MCPSRV --> CORE
    HTTP --> CORE
```

| Module | Responsibility |
| :--- | :--- |
| `token_parser.py`, `base64_url.py` | Compact JWT parsing and Base64URL codec |
| `claims_validator.py` | RFC 7519 temporal / issuer / audience checks |
| `crypto_engine.py` | HMAC signing and constant-time verification |
| `security_linter.py` | Vulnerability detection, scoring, secret cracking |
| `dpop_guard.py` | RFC 9449 DPoP proof creation and verification |
| `jwks_manager.py` | JWKS rotation simulation and RFC 7638 thumbprints |
| `timing_defense.py` | Comparison timing benchmarks |
| `ui_server.py` | Threaded HTTP server for `public/` and `/api/*` |
| `mcp_server.py` | JSON-RPC 2.0 MCP server over stdio |
| `cli.py` | argparse CLI dispatcher |

Additional launchers:

- `bin/jwt-inspector-guard` — Portable ZothOS Python CLI wrapper resolving `~/NullAITech/jwt-inspector-guard` or `/opt/jwt-inspector-guard` without overriding caller `cwd`, delegating `--status` to `:8124/health`, and redacting home paths in `--json`.
- `bin/jwt-inspector-guard-tui` — Live Unicode `U+2800` Braille telemetry TUI displaying real `:8124` status, 25-sample Shannon entropy spectrum, 1,954-secret wordlist size, and live ECDSA P-256 DPoP self-check (`--status`, `--json`).
- `jwt-inspector-guard.desktop` — Linux desktop entry launching `/usr/local/bin/jwt-inspector-guard serve --open` and the Braille TUI via `zoth-konsole`.

## Install

Requires Python 3.9+. Node.js is only needed for the `bin/jwt-guard.js` launcher and the optional Electron shell.

```bash
git clone https://github.com/1nc0gn30/jwt-inspector-guard.git
cd jwt-inspector-guard
python3 -m pip install -e .

# Verify
jwt-inspector-guard --version
jwt-inspector-guard --help

# Start the web UI + REST API on http://127.0.0.1:8124
python3 server.py
# or: npm start
# or: jwt-inspector-guard serve --no-browser
```

Optional desktop shell:

```bash
npm install
npm run app
```

## CLI Reference

Entry points: `jwt-inspector-guard` and `jwt-guard` (both map to `jwt_inspector_guard.cli:main`). Global flags `--no-color`, `-q/--quiet`, `-v/--version` are accepted before or after a subcommand. Most subcommands accept `--json`. Tokens may be passed as an argument or piped on stdin.

| Command | Purpose |
| :--- | :--- |
| `--json` | Print platform and crypto diagnostics as JSON |
| `--status` | Probe `http://127.0.0.1:8124/health` and print a JSON status object |
| `decode [TOKEN]` | Decode header / payload / signature |
| `verify [TOKEN] -s SECRET [-a ALG] [--iss] [--aud] [--leeway]` | Verify signature and claims |
| `encode -p PAYLOAD [-s SECRET] [-a ALG] [--exp] [--sub] [--iss] [--aud] [--header]` | Mint and sign a token |
| `audit [TOKEN] [-s SECRET]` | Security lint report and score |
| `crack [TOKEN] [-w WORDLIST] [--max-attempts N]` | Dictionary attack on HMAC secret |
| `samples` / `catalog [-c CATEGORY] [-g NAME]` | Built-in sample tokens and CVE vectors |
| `serve [--host H] [-p PORT] [--no-browser]` | Web UI + REST API (default `127.0.0.1:8124`) |
| `mcp` | MCP stdio server |
| `diagnostics` / `doctor` / `platform` | Platform and crypto diagnostics |
| `test` | Built-in self-test runner |
| `jwks [--rotate] [-f FILE] [--resolve TOKEN]` | JWKS audit and rotation simulation |
| `timing [--test-vulnerable] [--trials N]` | Comparison timing benchmark |
| `dpop-create [-m METHOD] [-u URL] [-t TOKEN] [-n NONCE]` | Create a DPoP proof |
| `dpop-verify PROOF [-m] [-u] [-t] [-n] [--jkt=THUMBPRINT] [--max-age]` | Verify a DPoP proof (use `--jkt=` form; base64url thumbprints can begin with `-`) |

Examples:

```bash
jwt-inspector-guard catalog
TOKEN=$(jwt-inspector-guard catalog -g weak-secret-jwt)
jwt-inspector-guard audit "$TOKEN" --json
jwt-inspector-guard crack "$TOKEN"
jwt-inspector-guard encode -p '{"sub":"usr_42"}' -s 'replace-with-a-long-random-secret' --exp 3600
jwt-inspector-guard dpop-create -m POST -u https://api.example.com/v1/orders --json
```

## MCP and REST Reference

### MCP (stdio)

```json
{
  "mcpServers": {
    "jwt-inspector-guard": {
      "command": "python3",
      "args": ["-m", "jwt_inspector_guard", "mcp"]
    }
  }
}
```

Tools: `jwt_decode`, `jwt_verify`, `jwt_encode`, `jwt_audit_security`, `jwt_crack_secret`, `jwt_list_samples`, `jwt_diagnostics`, `jwt_audit_jwks`, `jwt_timing_defense_audit`, `jwt_create_dpop_proof`, `jwt_verify_dpop_proof`.

### REST (`server.py`, `127.0.0.1:8124`)

`POST` routes take a JSON body and reject cross-origin requests (Origin guard).

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/health`, `/api/health` | Health and version |
| `POST` | `/api/decode` | Decode token |
| `POST` | `/api/verify`, `/api/validate` | Signature / claims validation |
| `POST` | `/api/audit` | Security lint report |
| `POST` | `/api/inspect` | Decode + validate + audit in one call |
| `POST` | `/api/catalog` | Sample tokens |
| `POST` | `/api/crack` | Weak-secret dictionary attack |
| `POST` | `/api/mint` | Sign a new token |
| `POST` | `/api/entropy` | Secret entropy estimate |
| `POST` | `/api/tamper` | Header/payload tampering helpers |
| `POST` | `/api/jwks` | JWKS audit / rotation |
| `POST` | `/api/timing` | Timing benchmark |
| `POST` | `/api/dpop/create`, `/api/dpop/verify` | DPoP proofs |

```bash
curl -s http://127.0.0.1:8124/health
curl -s -X POST http://127.0.0.1:8124/api/catalog -H 'Content-Type: application/json' -d '{}'
```

## Port

`127.0.0.1:8124` — matches the `jwt-inspector-guard` entry in Zoth Studio v2 `tools.json`. Override with `PORT` (for `server.py`, `bin/jwt-guard.js`, `electron/main.cjs`) or `JWT_GUARD_PORT` / `--port` (for `jwt-inspector-guard serve`). On ZothOS v3.4.0 the `jwt-guard` binary and `jwt-inspector.desktop` launcher use the same port.

## Testing

```bash
python3 -m pip install pytest
python3 -m pytest -q          # or: npm test
jwt-inspector-guard test      # built-in self-test
```

Server tests bind to ephemeral ports. `scripts/verify_ui.py` is an optional Playwright harness for triple-viewport UI checks against a running server (`JWT_GUARD_URL`).

## Support

JWT Inspector Guard is 100% free, open-access, and unlocked software with zero paywalls. Optional community support is available via:

- **Stripe**: [☕ Buy Us a Coffee](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **Solana Tip**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK` (`solana:GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`)

## License

MIT License — Engineered by Neal Frazier Tech ([`@1nc0gn30`](https://github.com/1nc0gn30)) • [NullAI Platform](https://nullai.tech). See [LICENSE](LICENSE).
