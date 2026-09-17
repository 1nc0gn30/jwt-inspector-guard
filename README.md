# JWT Inspector Guard 🛡️🔐

> **Multi-OS Model Context Protocol (MCP) Server, CLI & Google Material 3 Security Studio for JSON Web Tokens (JWT / JWS / JWE).**
> **Zero External Dependencies** — 100% Python Standard Library (3.9–3.13).

[![CI](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/1nc0gn30/jwt-inspector-guard/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastMCP](https://img.shields.io/badge/MCP-Protocol%202.0-green.svg)](https://modelcontextprotocol.io/)

---

## Overview

**JWT Inspector Guard** is an enterprise-grade security analysis tool and developer studio for JSON Web Tokens. Built entirely on Python's standard library (`hmac`, `hashlib`, `json`, `base64`), it decodes, verifies, and audits tokens without requiring external cryptography libraries like `cryptography` or `PyJWT`. It acts as an autonomous vulnerability auditor detecting CVE bypasses, algorithm confusion attacks, weak signing secrets, header injection flaws, and PII leaks.

---

## Key Features

- **Zero-Dependency Token Decoder**:
  - Full breakdown of JOSE header, payload claims, and signature.
  - Base64URL decoding with automatic padding compensation and UTF-8 sanitization.
- **RFC 7519 Standards Claims Verification**:
  - Validates `exp` (expiration), `nbf` (not before), `iat` (issued at), `iss` (issuer), and `aud` (audience).
  - Configurable clock skew leeway tolerance (default: 60 seconds).
- **Cryptographic Signature Engine**:
  - Verification for **HS256**, **HS384**, and **HS512** using constant-time `hmac.compare_digest`.
  - Signature calculation and token minting for development testing.
- **Deep Security Vulnerability Linter**:
  - **CVE-2015-9235**: `alg: none` detection and case-insensitive algorithm bypass filtering (`None`, `nOnE`).
  - **Algorithm Confusion Attacks**: Detects tokens signed with public keys treated as HMAC secrets.
  - **Weak Key Dictionary Attack**: High-speed dictionary cracker checking against common passwords, defaults, and weak strings.
  - **Credential & PII Leak Scanner**: Identifies passwords, auth tokens, database connection URIs, private keys, emails, and SSNs accidentally placed in payloads.
  - **Header Injection Vectors**: Audits `jku`, `x5u`, `jwk`, and path-traversal in `kid`.
- **FastMCP Protocol 2.0 Server**:
  - Built-in stdio JSON-RPC server exposing tools, resources, and prompts to Claude Desktop, Cursor, Cline, and Antigravity.
- **Google Material 3 Security Studio UI**:
  - Interactive dual-panel web interface with live decoding, vulnerability flags, signature checker, and dark/light modes.
- **Multi-OS CLI**:
  - Clean terminal tool with ANSI styling, `--no-color`, `-v`/`--version`, `-q`/`--quiet`, and JSON output.

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

## CLI Reference

```bash
# 1. Decode a token into formatted JSON
jwt-guard decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Verify signature & claims
jwt-guard verify "eyJhbGciOiJIUzI1Ni..." --secret "super-secret" --algorithm HS256

# 3. Comprehensive security vulnerability audit
jwt-guard audit "eyJhbGciOiJIUzI1Ni..."

# 4. Dictionary attack against weak HMAC secrets
jwt-guard crack "eyJhbGciOiJIUzI1Ni..."

# 5. List built-in attack vectors & test tokens
jwt-guard samples

# 6. Launch the Google Material 3 Security Studio Web UI
jwt-guard serve --port 8780
```

---

## FastMCP Configuration

Integrate JWT Inspector Guard into your AI coding environment:

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "jwt-guard": {
      "command": "jwt-guard",
      "args": ["mcp"]
    }
  }
}
```

### Cursor / Cline / Antigravity (`mcp.json`)

```json
{
  "mcpServers": {
    "jwt-guard": {
      "command": "python3",
      "args": ["-m", "jwt_inspector_guard", "mcp"]
    }
  }
}
```

### Registered MCP Tools:
- `jwt_decode`: Parse JOSE header, claims payload, and signature without external libs.
- `jwt_verify`: Validate cryptographic HMAC signature and RFC 7519 time-based claims.
- `jwt_audit`: Security audit against known CVEs, weak secrets, and PII leaks.
- `jwt_crack`: Dictionary attack to recover weak HMAC signing secrets.
- `jwt_mint`: Mint standard test tokens for automated QA and integration tests.
- `jwt_diagnostics`: Multi-OS runtime diagnostics.

---

## Python API Usage

```python
from jwt_inspector_guard import decode_token, verify_token, audit_token

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Decode
header, payload, sig = decode_token(token)
print("Algorithm:", header.get("alg"))
print("Subject:", payload.get("sub"))

# Security Audit
report = audit_token(token)
print("Security Score:", report.score)
for finding in report.findings:
    print(f"[{finding.severity}] {finding.title}: {finding.description}")
```

---

## Cross-Platform Compatibility

Tested and guaranteed across:
- **Linux**: Ubuntu 20.04+, Debian, Fedora, Arch Linux, Parrot OS
- **macOS**: Sonoma, Ventura, Monterey (Apple Silicon & Intel)
- **Windows**: Windows 10/11 (PowerShell, CMD, WSL)
- **Mobile / Android**: Termux
- **Python**: 3.9, 3.10, 3.11, 3.12, 3.13

---

## License

MIT License. Crafted with zero external dependencies using 100% Python Standard Library.
