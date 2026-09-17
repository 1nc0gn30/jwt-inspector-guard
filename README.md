# JWT Inspector Guard

> **Multi-OS Model Context Protocol (MCP) Server, CLI & Google Material 3 Security Studio for JSON Web Tokens (JWT / JWS / JWE).**
> **Zero External Dependencies** — 100% Python Standard Library (3.9–3.13).

[![CI](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Features

- **Decode & Parse**: Full 3-part (or JWE 5-part) token breakdown without external crypto libraries.
- **RFC 7519 Claims Validation**: Validate `exp`, `nbf`, `iat`, `iss`, `aud` with configurable clock leeway.
- **HMAC Signature Verification**: Fast HS256, HS384, and HS512 verification via Python's built-in `hmac` and `hashlib`.
- **Security Vulnerability Linter**:
  - Detects **CVE-2015-9235** (`alg: none` / case-insensitive filter bypass).
  - Weak secret key detection via built-in dictionary attack engine.
  - Sensitive credential & PII leakage detection (passwords, tokens, API keys, SSNs, credit cards).
  - Header injection vectors (`jku`, `x5u`, `jwk`, and path-traversal `kid`).
- **FastMCP Protocol Server**: Stdio JSON-RPC 2.0 server for Claude Desktop, Cursor, Cline, and Antigravity.
- **Google Material 3 Studio Web App**: Interactive UI with dark/light mode, live decoding, and real-time security scorecards.
- **Multi-OS CLI**: Native subcommands with `--no-color`, `-v`/`--version`, `-q`/`--quiet` flags.

---

## Installation

```bash
pip install jwt-inspector-guard
```

Or from source:

```bash
git clone https://github.com/1nc0gn30/jwt-inspector-guard.git
cd jwt-inspector-guard
pip install -e .
```

---

## CLI Usage

```bash
# 1. Decode a JWT token
jwt-guard decode <token>

# 2. Verify signature & validate claims
jwt-guard verify <token> --secret "my-secret" --algorithm HS256

# 3. Security audit report
jwt-guard audit <token>

# 4. Dictionary crack weak HMAC secret
jwt-guard crack <token>

# 5. List sample tokens and CVE vectors
jwt-guard samples

# 6. Launch Google Material 3 Studio Web UI
jwt-guard serve --port 8080

# 7. Run MCP stdio server
jwt-guard mcp
```

---

## MCP Server Integration

Add to your `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "jwt-inspector-guard": {
      "command": "jwt-guard",
      "args": ["mcp"]
    }
  }
}
```

### Available MCP Tools
- `jwt_decode`: Decode compact JWT into header, claims payload, signature, and timestamps.
- `jwt_verify`: Verify HMAC signature and validate standard RFC claims.
- `jwt_encode`: Mint and sign custom JWTs.
- `jwt_audit_security`: Scan token against CVE-2015-9235, weak keys, and PII leaks.
- `jwt_crack_secret`: Run dictionary attack against HMAC signing key.
- `jwt_list_samples`: List built-in samples and exploit test vectors.
- `jwt_diagnostics`: System environment diagnostics.

---

## License

MIT © [1nc0gn30](https://github.com/1nc0gn30)
