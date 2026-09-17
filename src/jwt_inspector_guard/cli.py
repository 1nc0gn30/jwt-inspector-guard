"""Multi-OS Command-Line Interface for JWT Inspector Guard.

Provides CLI subcommands:
  decode       - Decode and display colored 3-part token breakdown
  verify       - Verify HMAC signature and validate claims against expected values
  encode       - Mint and sign new JWTs with custom claims and header
  audit        - Run comprehensive security audit and output risk scorecard
  crack        - Dictionary attack weak HMAC secret keys
  samples      - List and inspect built-in sample JWTs and CVE vectors
  serve        - Launch JWT Studio Web UI & REST API (Material 3 influenced)
  mcp          - Run Model Context Protocol (MCP) server over stdio
  diagnostics  - Display multi-OS platform and crypto diagnostics
  test         - Run internal self-verification test runner

Supports global flags (--no-color, -v/--version, -q/--quiet) before or after any subcommand.
"""

from __future__ import annotations

import argparse
import datetime
import http.server
import json
import os
import platform
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from typing import Any, Dict, List, Optional, Tuple, Union

from .mcp_server import (
    COMMON_SECRETS,
    PROTOCOL_VERSION,
    SAMPLE_TOKENS_CATALOG,
    SERVER_NAME,
    SERVER_VERSION,
    audit_jwt_security,
    base64url_decode,
    base64url_encode,
    crack_jwt_secret,
    decode_jwt_parts,
    format_timestamp,
    get_diagnostics,
    get_sample_token,
    handle_jsonrpc_request,
    list_sample_tokens,
    run_stdio_server,
    sign_hmac,
    validate_claims,
    verify_hmac,
)

# ---------------------------------------------------------------------------
# ANSI Terminal Color Helpers (Cross-Platform & Windows Terminal Aware)
# ---------------------------------------------------------------------------

USE_COLOR = True


def configure_color(force_no_color: bool = False) -> None:
    """Configure ANSI color output based on TTY, environment, and user flags."""
    global USE_COLOR
    if force_no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        USE_COLOR = False
    else:
        USE_COLOR = True
        # Enable ANSI colors on Windows 10/11 if supported
        if platform.system() == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


def c_str(text: str, color_code: str) -> str:
    """Wrap text in ANSI escape sequence if coloring is enabled."""
    if not USE_COLOR:
        return text
    return f"{color_code}{text}\033[0m"


# Color palettes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Segment colors matching jwt.io and Material 3 design:
# Header: Red/Coral, Payload: Magenta/Purple, Signature: Cyan/Teal
HEADER_CLR = "\033[38;5;203m" if sys.platform != "win32" else RED
PAYLOAD_CLR = "\033[38;5;177m" if sys.platform != "win32" else MAGENTA
SIG_CLR = "\033[38;5;75m" if sys.platform != "win32" else CYAN


def print_banner(quiet: bool = False) -> None:
    """Print ASCII logo banner unless quiet mode is active."""
    if quiet:
        return
    banner = f"""{c_str('┌──────────────────────────────────────────────────────────┐', BLUE)}
{c_str('│', BLUE)}  {c_str('🛡️  JWT INSPECTOR GUARD', BOLD + CYAN)} {c_str(f'v{SERVER_VERSION}', DIM)}                 {c_str('│', BLUE)}
{c_str('│', BLUE)}  {c_str('MCP Server, CLI & Security Auditor for JSON Web Tokens', DIM)}  {c_str('│', BLUE)}
{c_str('└──────────────────────────────────────────────────────────┘', BLUE)}"""
    print(banner)


# ---------------------------------------------------------------------------
# CLI Subcommand Implementations
# ---------------------------------------------------------------------------

def read_token_input(token_arg: Optional[str]) -> str:
    """Read token string from argument or standard input."""
    if not token_arg or token_arg == "-":
        if sys.stdin.isatty():
            print(c_str("Enter JWT token: ", DIM), end="", file=sys.stderr, flush=True)
        return sys.stdin.readline().strip()
    return token_arg.strip()


def cmd_decode(args: argparse.Namespace) -> int:
    """Handle 'decode' subcommand."""
    token = read_token_input(args.token)
    if not token:
        print(c_str("Error: No JWT token provided.", RED), file=sys.stderr)
        return 1

    try:
        header, payload, sig_b64, header_b64, payload_b64, raw_token = decode_jwt_parts(token)
    except Exception as e:
        print(c_str(f"Error parsing JWT: {e}", RED), file=sys.stderr)
        return 1

    alg = header.get("alg", "none")
    typ = header.get("typ", "JWT")
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    if args.json:
        out = {
            "valid_format": True,
            "algorithm": alg,
            "token_type": typ,
            "header": header,
            "payload": payload,
            "signature_b64": sig_b64,
            "signature_bytes": len(base64url_decode(sig_b64)) if sig_b64 else 0,
            "formatted_claims": {
                "exp": format_timestamp(exp) if exp is not None else None,
                "iat": format_timestamp(iat) if iat is not None else None,
                "nbf": format_timestamp(nbf) if nbf is not None else None,
            },
            "raw_segments": {
                "header_b64": header_b64,
                "payload_b64": payload_b64,
                "signature_b64": sig_b64,
            }
        }
        print(json.dumps(out, indent=2))
        return 0

    print_banner(args.quiet)
    print()
    print(f"{c_str('TOKEN BREAKDOWN:', BOLD)}")
    print(f"  {c_str(header_b64, HEADER_CLR)}.{c_str(payload_b64, PAYLOAD_CLR)}.{c_str(sig_b64 or '(empty)', SIG_CLR)}")
    print()

    # Header Box
    print(f"{c_str('┌─ HEADER: ALGORITHM & TOKEN TYPE', HEADER_CLR + BOLD)}")
    for line in json.dumps(header, indent=2).splitlines():
        print(f"{c_str('│', HEADER_CLR)}  {line}")
    print(f"{c_str('└───────────────────────────────────', HEADER_CLR)}")
    print()

    # Payload Box
    print(f"{c_str('┌─ PAYLOAD: DATA & CLAIMS', PAYLOAD_CLR + BOLD)}")
    for line in json.dumps(payload, indent=2).splitlines():
        print(f"{c_str('│', PAYLOAD_CLR)}  {line}")
    print(f"{c_str('└───────────────────────────────────', PAYLOAD_CLR)}")
    print()

    # Signature & Claims Summary
    print(f"{c_str('┌─ SIGNATURE & CLAIMS METRICS', SIG_CLR + BOLD)}")
    print(f"{c_str('│', SIG_CLR)}  Algorithm: {c_str(alg, BOLD + WHITE)} ({typ})")
    print(f"{c_str('│', SIG_CLR)}  Signature Length: {len(base64url_decode(sig_b64)) if sig_b64 else 0} bytes")

    # Time claims evaluation
    now = time.time()
    if exp is not None:
        try:
            exp_val = float(exp)
            diff = exp_val - now
            if diff > 0:
                print(f"{c_str('│', SIG_CLR)}  Expires At: {format_timestamp(exp_val)} {c_str(f'(valid for {int(diff // 60)}m {int(diff % 60)}s)', GREEN)}")
            else:
                print(f"{c_str('│', SIG_CLR)}  Expires At: {format_timestamp(exp_val)} {c_str(f'(EXPIRED {abs(int(diff // 60))}m ago)', RED + BOLD)}")
        except Exception:
            print(f"{c_str('│', SIG_CLR)}  Expires At: {exp} (invalid format)")
    else:
        print(f"{c_str('│', SIG_CLR)}  Expires At: {c_str('Never (missing exp claim)', YELLOW)}")

    if iat is not None:
        print(f"{c_str('│', SIG_CLR)}  Issued At:  {format_timestamp(iat)}")
    if nbf is not None:
        print(f"{c_str('│', SIG_CLR)}  Not Before: {format_timestamp(nbf)}")

    print(f"{c_str('└───────────────────────────────────', SIG_CLR)}")
    print()
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle 'verify' subcommand."""
    token = read_token_input(args.token)
    if not token:
        print(c_str("Error: No JWT token provided.", RED), file=sys.stderr)
        return 1

    try:
        header, payload, sig_b64, _, _, _ = decode_jwt_parts(token)
    except Exception as e:
        print(c_str(f"Error: Malformed JWT: {e}", RED), file=sys.stderr)
        return 1

    alg = (args.alg or header.get("alg", "HS256")).upper()
    secret = args.secret or ""
    leeway = float(args.leeway or 0.0)

    # Signature verification
    sig_valid: Optional[bool] = None
    if secret or alg == "NONE":
        sig_valid = verify_hmac(token, secret, alg)

    # Claims validation
    claims_res = validate_claims(
        payload,
        issuer=args.iss,
        audience=args.aud,
        leeway=leeway
    )

    is_overall_valid = (sig_valid is True or (sig_valid is None and not secret)) and claims_res["claims_valid"]

    if args.json:
        out = {
            "is_valid": is_overall_valid,
            "signature_valid": sig_valid,
            "claims_valid": claims_res["claims_valid"],
            "algorithm": alg,
            "is_expired": claims_res["is_expired"],
            "time_to_expiry_seconds": claims_res["time_to_expiry_seconds"],
            "errors": claims_res["errors"],
            "warnings": claims_res["warnings"],
            "formatted_dates": claims_res["formatted_dates"],
            "header": header,
            "payload": payload,
        }
        print(json.dumps(out, indent=2))
        return 0 if is_overall_valid else 1

    print_banner(args.quiet)
    print()

    # Overall Verdict
    if is_overall_valid:
        print(f"{c_str('  ✔ VERIFICATION PASSED: Token is valid.', GREEN + BOLD)}")
    else:
        print(f"{c_str('  ✖ VERIFICATION FAILED: Token is invalid.', RED + BOLD)}")
    print()

    # Signature Details
    if sig_valid is True:
        print(f"  • Signature ({alg}): {c_str('VALID', GREEN + BOLD)}")
    elif sig_valid is False:
        print(f"  • Signature ({alg}): {c_str('INVALID (Secret mismatch or tampered payload)', RED + BOLD)}")
    else:
        print(f"  • Signature ({alg}): {c_str('UNVERIFIED (No --secret provided)', YELLOW)}")

    # Claims Details
    print(f"  • Claims Validation:  {c_str('PASSED' if claims_res['claims_valid'] else 'FAILED', GREEN if claims_res['claims_valid'] else RED)}")

    if claims_res["errors"]:
        print()
        print(f"  {c_str('Validation Errors:', RED + BOLD)}")
        for err in claims_res["errors"]:
            print(f"    - {c_str(err, RED)}")

    if claims_res["warnings"]:
        print()
        print(f"  {c_str('Warnings:', YELLOW + BOLD)}")
        for warn in claims_res["warnings"]:
            print(f"    - {c_str(warn, YELLOW)}")

    print()
    return 0 if is_overall_valid else 1


def cmd_encode(args: argparse.Namespace) -> int:
    """Handle 'encode' subcommand."""
    # Parse payload
    raw_payload = args.payload
    if not raw_payload:
        if not sys.stdin.isatty():
            raw_payload = sys.stdin.read().strip()
        else:
            raw_payload = "{}"

    if raw_payload.startswith("@") or os.path.exists(raw_payload):
        filepath = raw_payload[1:] if raw_payload.startswith("@") else raw_payload
        with open(filepath, "r", encoding="utf-8") as f:
            raw_payload = f.read()

    try:
        payload_dict = json.loads(raw_payload)
    except Exception as e:
        print(c_str(f"Error parsing payload JSON: {e}", RED), file=sys.stderr)
        return 1

    # Inject convenience claims if specified
    now = int(time.time())
    if args.sub:
        payload_dict["sub"] = args.sub
    if args.iss:
        payload_dict["iss"] = args.iss
    if args.aud:
        payload_dict["aud"] = args.aud
    if args.exp:
        try:
            exp_val = int(args.exp)
            # If exp is relative seconds (e.g. 3600), add to now
            if exp_val < 1000000000:
                payload_dict["iat"] = now
                payload_dict["exp"] = now + exp_val
            else:
                payload_dict["exp"] = exp_val
        except ValueError:
            print(c_str(f"Error: Invalid exp seconds '{args.exp}'", RED), file=sys.stderr)
            return 1

    # Parse custom header if provided
    alg = args.alg or "HS256"
    if args.header:
        try:
            header_dict = json.loads(args.header)
        except Exception as e:
            print(c_str(f"Error parsing header JSON: {e}", RED), file=sys.stderr)
            return 1
    else:
        header_dict = {"alg": alg, "typ": "JWT"}

    secret = args.secret or ""
    token = sign_hmac(header_dict, payload_dict, secret, alg)

    if args.json:
        out = {
            "token": token,
            "algorithm": alg,
            "header": header_dict,
            "payload": payload_dict,
            "expires_at": format_timestamp(payload_dict.get("exp")),
            "issued_at": format_timestamp(payload_dict.get("iat")),
        }
        print(json.dumps(out, indent=2))
    else:
        if not args.quiet:
            print(c_str("MINTED JWT TOKEN:", BOLD + GREEN))
        print(token)

    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Handle 'audit' subcommand."""
    token = read_token_input(args.token)
    if not token:
        print(c_str("Error: No JWT token provided.", RED), file=sys.stderr)
        return 1

    report = audit_jwt_security(token, known_secret=args.secret)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if report["is_secure"] else 1

    print_banner(args.quiet)
    print()

    # Scorecard Header
    score = report["score"]
    grade = report["grade"]
    risk = report["risk_level"]

    grade_color = GREEN if grade in ["A", "B"] else (YELLOW if grade == "C" else RED)

    print(f"{c_str('╔══════════════════════════════════════════════════════════╗', BOLD + WHITE)}")
    print(f"{c_str('║', BOLD + WHITE)}  {c_str('SECURITY AUDIT SCORECARD', BOLD + CYAN)}                            {c_str('║', BOLD + WHITE)}")
    print(f"{c_str('║', BOLD + WHITE)}  Score: {c_str(f'{score}/100', grade_color + BOLD)}  |  Grade: {c_str(grade, grade_color + BOLD)}  |  Risk: {c_str(risk, grade_color + BOLD)}   {c_str('║', BOLD + WHITE)}")
    print(f"{c_str('╚══════════════════════════════════════════════════════════╝', BOLD + WHITE)}")
    print()

    # Findings
    findings = report.get("findings", [])
    if not findings:
        print(f"  {c_str('✔ No security vulnerabilities found. Excellent token hygiene!', GREEN + BOLD)}")
    else:
        print(f"{c_str('FINDINGS & VULNERABILITIES:', BOLD)}")
        for f in findings:
            sev = f["severity"]
            sev_clr = RED if sev in ["CRITICAL", "HIGH"] else (YELLOW if sev == "MEDIUM" else BLUE)
            cve_str = f" [{f['cve']}]" if f.get("cve") else ""
            print(f"  {c_str(f'[{sev}]', sev_clr + BOLD)} {c_str(f['title'] + cve_str, BOLD)}")
            print(f"    {c_str('Issue:', DIM)} {f['description']}")
            if f.get("remediation"):
                print(f"    {c_str('Fix:', GREEN)}   {f['remediation']}")
            print()

    # Recommendations
    recs = report.get("recommendations", [])
    if recs:
        print(f"{c_str('ACTIONABLE RECOMMENDATIONS:', BOLD + CYAN)}")
        for idx, rec in enumerate(recs, 1):
            print(f"  {idx}. {rec}")
        print()

    return 0 if report["is_secure"] else 1


def cmd_crack(args: argparse.Namespace) -> int:
    """Handle 'crack' subcommand."""
    token = read_token_input(args.token)
    if not token:
        print(c_str("Error: No JWT token provided.", RED), file=sys.stderr)
        return 1

    wordlist: Optional[List[str]] = None
    if args.wordlist:
        if not os.path.exists(args.wordlist):
            print(c_str(f"Error: Wordlist file '{args.wordlist}' does not exist.", RED), file=sys.stderr)
            return 1
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]

    max_att = int(args.max_attempts or 5000)
    result = crack_jwt_secret(token, wordlist=wordlist, max_attempts=max_att)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["cracked"] else 1

    print_banner(args.quiet)
    print()
    if result["cracked"]:
        print(f"{c_str('  💥 VULNERABILITY CONFIRMED: Weak HMAC Secret Cracked!', RED + BOLD)}")
        print(f"  • Cracked Secret Key: {c_str(result['secret'], BOLD + WHITE + RED)}")
        print(f"  • Algorithm:         {result['algorithm']}")
        print(f"  • Attempts:          {result['attempts']}")
        print(f"  • Elapsed Time:      {result['time_seconds']}s")
        print()
        print(f"  {c_str('Remediation:', GREEN)} Rotate signing secret immediately with at least 256 bits of cryptographically secure random bytes.")
    else:
        print(f"{c_str('  🛡️  SECRET NOT FOUND in dictionary.', GREEN + BOLD)}")
        print(f"  • Attempts:     {result['attempts']}")
        print(f"  • Elapsed Time: {result['time_seconds']}s")
        if result.get("error"):
            print(f"  • Note:         {result['error']}")
    print()
    return 0 if result["cracked"] else 1


def cmd_samples(args: argparse.Namespace) -> int:
    """Handle 'samples' subcommand."""
    if args.get:
        sample = get_sample_token(args.get)
        if not sample:
            print(c_str(f"Error: Sample token '{args.get}' not found.", RED), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(sample, indent=2))
        else:
            print(sample["token"])
        return 0

    category = args.category or "all"
    samples = list_sample_tokens(category=category)

    if args.json:
        print(json.dumps(samples, indent=2))
        return 0

    print_banner(args.quiet)
    print()
    print(f"{c_str('JWT SAMPLES & CVE ATTACK CATALOG:', BOLD + CYAN)} (Category: {category})")
    print()
    for s in samples:
        cat_clr = RED if s["category"] in ["vulnerabilities", "attacks"] else GREEN
        print(f"  • {c_str(s['name'], BOLD + WHITE)} [{c_str(s['category'], cat_clr)}]")
        print(f"    {s['description']}")
        print(f"    {c_str('Notes:', DIM)} {s['vulnerability_notes']}")
        print(f"    {c_str('Token:', DIM)} {s['token'][:60]}...")
        print()

    print(f"Use {c_str('jwt-guard samples --get <name>', CYAN)} or {c_str('jwt-guard decode $(jwt-guard samples --get <name>)', CYAN)} to inspect.")
    print()
    return 0


def cmd_diagnostics(args: argparse.Namespace) -> int:
    """Handle 'diagnostics' / 'doctor' / 'platform' subcommand."""
    diag = get_diagnostics()

    if args.json:
        print(json.dumps(diag, indent=2))
        return 0

    print_banner(args.quiet)
    print()
    print(f"{c_str('MULTI-OS DIAGNOSTIC REPORT:', BOLD + CYAN)}")
    print()
    print(f"  {c_str('Platform:', BOLD)}")
    print(f"    OS:             {diag['platform']['system']} {diag['platform']['release']} ({diag['platform']['machine']})")
    print(f"    Python:         {diag['platform']['python_version']} ({diag['platform']['python_implementation']})")
    print(f"    Byte Order:     {diag['platform']['endianness']}-endian")
    print()
    print(f"  {c_str('Crypto Engine:', BOLD)}")
    print(f"    HMAC Hashes:    {', '.join(diag['crypto']['available_hmac_hashes'])}")
    print(f"    Zero-Dep:       {c_str('YES (Pure Python Standard Library)', GREEN)}")
    print()
    print(f"  {c_str('Protocol & Server:', BOLD)}")
    print(f"    MCP Server:     {diag['server']['name']} v{diag['server']['version']}")
    print(f"    Protocol Ver:   {diag['server']['protocol_version']}")
    print(f"    Secrets Count:  {diag['audit_engine']['built_in_secrets_count']} built-in weak keys")
    print(f"    Sample Vectors: {diag['audit_engine']['sample_tokens_count']} catalog items")
    print()
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Handle 'mcp' subcommand: run MCP server over stdio."""
    run_stdio_server()
    return 0


# ---------------------------------------------------------------------------
# Material 3 JWT Studio Web UI & REST Server
# ---------------------------------------------------------------------------

MATERIAL_3_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JWT Inspector Guard Studio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #0f111a;
      --bg-surface: #181a27;
      --bg-surface-elevated: #212435;
      --bg-surface-container: #2b2f44;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-focus: #82aaff;
      --text-primary: #e6edf3;
      --text-secondary: #90a4ae;
      --text-muted: #607d8b;
      --clr-header: #ff5370;
      --clr-payload: #c792ea;
      --clr-signature: #89ddff;
      --clr-success: #c3e88d;
      --clr-warning: #ffcb6b;
      --clr-critical: #f07178;
      --radius-sm: 8px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --shadow-elevation: 0 10px 30px -10px rgba(0,0,0,0.5);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--text-primary);
    }
    .logo span.badge {
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 999px;
      background: var(--bg-surface-container);
      color: var(--clr-signature);
      border: 1px solid var(--border-subtle);
    }
    .main-container {
      flex: 1;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      padding: 1.5rem 2rem;
      max-width: 1800px;
      margin: 0 auto;
      width: 100%;
    }
    @media (max-width: 1024px) {
      .main-container { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--bg-surface);
      border-radius: var(--radius-md);
      border: 1px solid var(--border-subtle);
      box-shadow: var(--shadow-elevation);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .card-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--bg-surface-elevated);
    }
    .card-title {
      font-size: 0.95rem;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .card-body { padding: 1.25rem; flex: 1; display: flex; flex-direction: column; gap: 1rem; }
    textarea, input, select {
      width: 100%;
      background: var(--bg-base);
      color: var(--text-primary);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 0.75rem;
      font-family: 'Fira Code', monospace;
      font-size: 0.88rem;
      transition: all 0.2s ease;
    }
    textarea:focus, input:focus, select:focus {
      outline: none;
      border-color: var(--border-focus);
      box-shadow: 0 0 0 2px rgba(130, 170, 255, 0.2);
    }
    #tokenInput { height: 220px; line-height: 1.4; resize: vertical; word-break: break-all; }
    .segmented-preview {
      padding: 0.75rem;
      background: var(--bg-base);
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-subtle);
      font-family: 'Fira Code', monospace;
      font-size: 0.82rem;
      word-break: break-all;
      max-height: 140px;
      overflow-y: auto;
    }
    .seg-header { color: var(--clr-header); }
    .seg-payload { color: var(--clr-payload); }
    .seg-sig { color: var(--clr-signature); }
    .tabs-nav {
      display: flex;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--bg-surface-elevated);
    }
    .tab-btn {
      padding: 0.75rem 1.25rem;
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
    }
    .tab-btn.active { color: var(--text-primary); border-bottom-color: var(--border-focus); background: var(--bg-surface); }
    .tab-content { display: none; padding: 1.25rem; flex: 1; flex-direction: column; gap: 1rem; }
    .tab-content.active { display: flex; }
    .scorecard-banner {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      padding: 1.25rem;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border: 1px solid var(--border-subtle);
    }
    .grade-circle {
      width: 70px;
      height: 70px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      font-weight: 800;
      background: var(--bg-surface-container);
      border: 3px solid var(--border-focus);
    }
    .finding-item {
      padding: 0.85rem;
      border-radius: var(--radius-sm);
      background: var(--bg-surface-elevated);
      border-left: 4px solid var(--clr-critical);
      margin-bottom: 0.75rem;
    }
    .btn {
      background: var(--border-focus);
      color: var(--bg-base);
      font-weight: 600;
      padding: 0.6rem 1.2rem;
      border-radius: var(--radius-sm);
      border: none;
      cursor: pointer;
      font-size: 0.85rem;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.9; }
    .btn-outline {
      background: transparent;
      color: var(--text-primary);
      border: 1px solid var(--border-subtle);
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <span>🛡️ JWT Inspector Guard</span>
      <span class="badge">Material 3 Studio</span>
    </div>
    <div style="display:flex; gap:0.75rem;">
      <select id="sampleSelect" style="width: 260px;" onchange="loadSample()">
        <option value="">-- Load Sample Token / CVE Vector --</option>
      </select>
    </div>
  </header>

  <div class="main-container">
    <!-- Left Column: Encoded Input -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Encoded Token</span>
        <button class="btn btn-outline" style="padding:4px 10px; font-size:0.75rem;" onclick="clearToken()">Clear</button>
      </div>
      <div class="card-body">
        <textarea id="tokenInput" placeholder="Paste JWT token here..." oninput="handleTokenChange()"></textarea>
        
        <div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); text-transform:uppercase;">Segment Breakdown</div>
        <div class="segmented-preview" id="segmentedView">
          <span class="seg-header">header</span>.<span class="seg-payload">payload</span>.<span class="seg-sig">signature</span>
        </div>

        <div style="margin-top:0.5rem; display:flex; flex-direction:column; gap:0.5rem;">
          <label style="font-size:0.8rem; font-weight:600; color:var(--text-secondary);">HMAC Verify Secret Key:</label>
          <div style="display:flex; gap:0.5rem;">
            <input type="text" id="secretInput" placeholder="Enter secret (e.g. your-256-bit-secret)" value="your-256-bit-secret" oninput="runVerify()">
            <button class="btn btn-outline" onclick="runCrack()">⚡ Crack</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Right Column: Decoded & Audited Panels -->
    <div class="card">
      <div class="tabs-nav">
        <button class="tab-btn active" onclick="switchTab('decodedTab', this)">Decoded & Claims</button>
        <button class="tab-btn" onclick="switchTab('auditTab', this)">Security Audit</button>
        <button class="tab-btn" onclick="switchTab('mintTab', this)">Mint / Encode</button>
      </div>

      <!-- Decoded Tab -->
      <div id="decodedTab" class="tab-content active">
        <div>
          <div style="font-size:0.8rem; font-weight:700; color:var(--clr-header); margin-bottom:0.4rem;">HEADER: Algorithm & Token Type</div>
          <textarea id="headerJson" style="height:120px; color:var(--clr-header);" readonly></textarea>
        </div>
        <div>
          <div style="font-size:0.8rem; font-weight:700; color:var(--clr-payload); margin-bottom:0.4rem;">PAYLOAD: Data & Claims</div>
          <textarea id="payloadJson" style="height:180px; color:var(--clr-payload);" readonly></textarea>
        </div>
        <div id="verifyStatusBadge" style="padding:0.75rem; border-radius:var(--radius-sm); font-weight:600; font-size:0.85rem; background:var(--bg-surface-elevated);">
          Signature Status: Checking...
        </div>
      </div>

      <!-- Security Audit Tab -->
      <div id="auditTab" class="tab-content">
        <div class="scorecard-banner">
          <div class="grade-circle" id="auditGrade">A</div>
          <div>
            <div style="font-size:1.1rem; font-weight:700;" id="auditRisk">SECURE</div>
            <div style="color:var(--text-secondary); font-size:0.85rem;" id="auditScore">Score: 100/100</div>
          </div>
        </div>
        <div style="font-weight:600; font-size:0.85rem; text-transform:uppercase; color:var(--text-muted);">Audit Findings</div>
        <div id="auditFindingsList" style="max-height: 280px; overflow-y:auto;"></div>
      </div>

      <!-- Mint Tab -->
      <div id="mintTab" class="tab-content">
        <div>
          <label style="font-size:0.8rem; font-weight:600; color:var(--text-secondary);">Algorithm</label>
          <select id="mintAlg" style="margin-top:0.25rem;">
            <option value="HS256">HS256 (HMAC SHA-256)</option>
            <option value="HS384">HS384 (HMAC SHA-384)</option>
            <option value="HS512">HS512 (HMAC SHA-512)</option>
            <option value="none">none (Unsecured)</option>
          </select>
        </div>
        <div>
          <label style="font-size:0.8rem; font-weight:600; color:var(--text-secondary);">Payload JSON</label>
          <textarea id="mintPayload" style="height:140px; margin-top:0.25rem;">{\n  "sub": "user_42",\n  "role": "admin",\n  "iss": "jwt-inspector-guard"\n}</textarea>
        </div>
        <div>
          <label style="font-size:0.8rem; font-weight:600; color:var(--text-secondary);">Signing Secret</label>
          <input type="text" id="mintSecret" value="super-secure-production-secret-key-32b">
        </div>
        <button class="btn" onclick="mintNewToken()">Generate & Sign Token</button>
      </div>
    </div>
  </div>

  <script>
    let samplesList = [];

    async function init() {
      try {
        const resp = await fetch('/api/samples');
        samplesList = await resp.json();
        const sel = document.getElementById('sampleSelect');
        samplesList.forEach((s, idx) => {
          const opt = document.createElement('option');
          opt.value = idx;
          opt.textContent = `[${s.category}] ${s.name}`;
          sel.appendChild(opt);
        });
        // Load default sample
        if (samplesList.length > 0) {
          sel.value = 0;
          loadSample();
        }
      } catch (e) {
        console.error("Failed to load samples:", e);
      }
    }

    function switchTab(tabId, btn) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }

    function loadSample() {
      const sel = document.getElementById('sampleSelect');
      if (sel.value === "") return;
      const sample = samplesList[parseInt(sel.value)];
      if (sample) {
        document.getElementById('tokenInput').value = sample.token;
        handleTokenChange();
      }
    }

    function clearToken() {
      document.getElementById('tokenInput').value = '';
      handleTokenChange();
    }

    async function handleTokenChange() {
      const token = document.getElementById('tokenInput').value.trim();
      const segView = document.getElementById('segmentedView');

      if (!token) {
        segView.innerHTML = '<span class="seg-header">header</span>.<span class="seg-payload">payload</span>.<span class="seg-sig">signature</span>';
        document.getElementById('headerJson').value = '';
        document.getElementById('payloadJson').value = '';
        return;
      }

      const parts = token.split('.');
      segView.innerHTML = `<span class="seg-header">${parts[0]||''}</span>.<span class="seg-payload">${parts[1]||''}</span>.<span class="seg-sig">${parts[2]||''}</span>`;

      // API Call to decode
      try {
        const res = await fetch('/api/decode', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({token})
        });
        const data = await res.json();
        if (data.valid_format) {
          document.getElementById('headerJson').value = JSON.stringify(data.header, null, 2);
          document.getElementById('payloadJson').value = JSON.stringify(data.payload, null, 2);
        }
      } catch (e) {
        console.error(e);
      }

      runVerify();
      runAudit();
    }

    async function runVerify() {
      const token = document.getElementById('tokenInput').value.trim();
      const secret = document.getElementById('secretInput').value;
      const badge = document.getElementById('verifyStatusBadge');

      if (!token) return;

      try {
        const res = await fetch('/api/verify', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({token, secret})
        });
        const data = await res.json();
        if (data.signature_valid === true) {
          badge.style.borderLeft = '4px solid var(--clr-success)';
          badge.textContent = `✔ Signature VALID (${data.algorithm}) | Claims: ${data.claims_valid ? 'Valid' : 'Invalid'}`;
        } else if (data.signature_valid === false) {
          badge.style.borderLeft = '4px solid var(--clr-critical)';
          badge.textContent = `✖ Signature INVALID (${data.algorithm}) | ${data.errors.join(', ')}`;
        } else {
          badge.style.borderLeft = '4px solid var(--clr-warning)';
          badge.textContent = `⚡ Signature Unverified (No secret)`;
        }
      } catch (e) {
        badge.textContent = 'Verification error';
      }
    }

    async function runAudit() {
      const token = document.getElementById('tokenInput').value.trim();
      if (!token) return;

      try {
        const res = await fetch('/api/audit', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({token})
        });
        const data = await res.json();
        const gradeEl = document.getElementById('auditGrade');
        gradeEl.textContent = data.grade;
        document.getElementById('auditRisk').textContent = data.risk_level;
        document.getElementById('auditScore').textContent = `Security Score: ${data.score}/100`;

        if (data.grade === 'A' || data.grade === 'B') gradeEl.style.borderColor = 'var(--clr-success)';
        else if (data.grade === 'C') gradeEl.style.borderColor = 'var(--clr-warning)';
        else gradeEl.style.borderColor = 'var(--clr-critical)';

        const list = document.getElementById('auditFindingsList');
        list.innerHTML = '';
        if (data.findings.length === 0) {
          list.innerHTML = '<div style="color:var(--clr-success); font-weight:600;">✔ No vulnerabilities identified.</div>';
        } else {
          data.findings.forEach(f => {
            const item = document.createElement('div');
            item.className = 'finding-item';
            if (f.severity === 'CRITICAL' || f.severity === 'HIGH') item.style.borderLeftColor = 'var(--clr-critical)';
            else if (f.severity === 'MEDIUM') item.style.borderLeftColor = 'var(--clr-warning)';
            else item.style.borderLeftColor = 'var(--clr-signature)';

            item.innerHTML = `
              <div style="font-weight:700; font-size:0.85rem;">[${f.severity}] ${f.title}</div>
              <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:2px;">${f.description}</div>
              ${f.remediation ? `<div style="font-size:0.78rem; color:var(--clr-success); margin-top:4px;"><b>Fix:</b> ${f.remediation}</div>` : ''}
            `;
            list.appendChild(item);
          });
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function runCrack() {
      const token = document.getElementById('tokenInput').value.trim();
      if (!token) return;
      try {
        const res = await fetch('/api/crack', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({token})
        });
        const data = await res.json();
        if (data.cracked) {
          alert(`💥 VULNERABILITY: Secret cracked! Found key: "${data.secret}" (${data.attempts} attempts, ${data.time_seconds}s)`);
          document.getElementById('secretInput').value = data.secret;
          runVerify();
        } else {
          alert(`Key not found in built-in dictionary (${data.attempts} attempts).`);
        }
      } catch (e) {
        alert('Error during dictionary crack: ' + e);
      }
    }

    async function mintNewToken() {
      const alg = document.getElementById('mintAlg').value;
      const payloadStr = document.getElementById('mintPayload').value;
      const secret = document.getElementById('mintSecret').value;

      try {
        const payload = JSON.parse(payloadStr);
        const res = await fetch('/api/encode', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({payload, secret, algorithm: alg, exp_seconds: 3600})
        });
        const data = await res.json();
        document.getElementById('tokenInput').value = data.token;
        document.getElementById('secretInput').value = secret;
        handleTokenChange();
        switchTab('decodedTab', document.querySelectorAll('.tab-btn')[0]);
      } catch (e) {
        alert('Failed to mint token: ' + e);
      }
    }

    window.onload = init;
  </script>
</body>
</html>"""


class JWTStudioHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler serving Material 3 UI and REST endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server access logs to keep terminal quiet."""
        pass

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(MATERIAL_3_HTML.encode("utf-8"))
        elif path == "/api/samples":
            samples = list_sample_tokens("all")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(samples).encode("utf-8"))
        elif path == "/api/diagnostics":
            diag = get_diagnostics()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(diag).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        """Handle POST requests for REST API."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        resp_data: Dict[str, Any] = {}

        if path == "/api/decode":
            token = req_data.get("token", "")
            try:
                header, payload, sig_b64, header_b64, payload_b64, _ = decode_jwt_parts(token)
                resp_data = {
                    "valid_format": True,
                    "header": header,
                    "payload": payload,
                    "signature_b64": sig_b64,
                }
            except Exception as e:
                resp_data = {"valid_format": False, "error": str(e)}

        elif path == "/api/verify":
            token = req_data.get("token", "")
            secret = req_data.get("secret", "")
            algorithm = req_data.get("algorithm")
            try:
                header, payload, _, _, _, _ = decode_jwt_parts(token)
                alg = (algorithm or header.get("alg", "HS256")).upper()
                sig_valid = verify_hmac(token, secret, alg) if secret else None
                claims_res = validate_claims(payload)
                resp_data = {
                    "signature_valid": sig_valid,
                    "claims_valid": claims_res["claims_valid"],
                    "algorithm": alg,
                    "errors": claims_res["errors"],
                    "warnings": claims_res["warnings"],
                }
            except Exception as e:
                resp_data = {"error": str(e)}

        elif path == "/api/encode":
            payload = req_data.get("payload", {})
            secret = req_data.get("secret", "")
            alg = req_data.get("algorithm", "HS256")
            exp_seconds = req_data.get("exp_seconds")
            p_copy = dict(payload)
            now = int(time.time())
            if exp_seconds:
                p_copy["iat"] = now
                p_copy["exp"] = now + int(exp_seconds)
            header = {"alg": alg, "typ": "JWT"}
            token = sign_hmac(header, p_copy, secret, alg)
            resp_data = {"token": token, "header": header, "payload": p_copy}

        elif path == "/api/audit":
            token = req_data.get("token", "")
            resp_data = audit_jwt_security(token)

        elif path == "/api/crack":
            token = req_data.get("token", "")
            resp_data = crack_jwt_secret(token)

        elif path == "/api/mcp":
            resp = handle_jsonrpc_request(req_data)
            resp_data = resp if isinstance(resp, dict) else {"result": resp}

        self.wfile.write(json.dumps(resp_data).encode("utf-8"))


def cmd_serve(args: argparse.Namespace) -> int:
    """Handle 'serve' subcommand: Launch JWT Studio web server."""
    host = args.host or "127.0.0.1"
    port = int(args.port or 8080)

    server_address = (host, port)
    try:
        httpd = http.server.HTTPServer(server_address, JWTStudioHTTPHandler)
    except OSError as e:
        print(c_str(f"Error binding to {host}:{port}: {e}", RED), file=sys.stderr)
        return 1

    url = f"http://{host}:{port}/"
    print_banner(args.quiet)
    print()
    print(f"  {c_str('🚀 JWT Inspector Studio Web UI started!', GREEN + BOLD)}")
    print(f"  • Local URL:      {c_str(url, BOLD + CYAN)}")
    print(f"  • REST Endpoints: {c_str(f'http://{host}:{port}/api/decode', DIM)}, {c_str('/api/audit', DIM)}, {c_str('/api/crack', DIM)}")
    print(f"  • Press {c_str('Ctrl+C', BOLD)} to stop server.")
    print()

    if args.open and not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{c_str('Stopping server...', DIM)}")
    finally:
        httpd.server_close()
    return 0


# ---------------------------------------------------------------------------
# Self-Verification Test Suite
# ---------------------------------------------------------------------------

def cmd_test(args: argparse.Namespace) -> int:
    """Run internal test runner validating all features without external frameworks."""
    print(f"{c_str('Running JWT Inspector Guard Internal Self-Test Suite...', BOLD + CYAN)}")
    passed = 0
    failed = 0

    def assert_true(expr: bool, name: str) -> None:
        nonlocal passed, failed
        if expr:
            print(f"  {c_str('✔ PASS:', GREEN)} {name}")
            passed += 1
        else:
            print(f"  {c_str('✖ FAIL:', RED + BOLD)} {name}")
            failed += 1

    # Test 1: Base64URL
    data = b"Hello, JWT Inspector World! 12345"
    encoded = base64url_encode(data)
    decoded = base64url_decode(encoded)
    assert_true(decoded == data, "Base64URL roundtrip encoding/decoding")

    # Test 2: HMAC Sign & Verify
    secret = "test-secret-256-bit-key-here"
    token_hs256 = sign_hmac({"alg": "HS256"}, {"sub": "123", "name": "Test"}, secret, "HS256")
    assert_true(verify_hmac(token_hs256, secret, "HS256"), "HMAC HS256 sign & verify match")
    assert_true(not verify_hmac(token_hs256, "wrong-secret", "HS256"), "HMAC HS256 rejects incorrect secret")

    # Test 3: HS384 and HS512
    token_hs384 = sign_hmac({"alg": "HS384"}, {"sub": "384"}, secret, "HS384")
    token_hs512 = sign_hmac({"alg": "HS512"}, {"sub": "512"}, secret, "HS512")
    assert_true(verify_hmac(token_hs384, secret, "HS384"), "HMAC HS384 sign & verify")
    assert_true(verify_hmac(token_hs512, secret, "HS512"), "HMAC HS512 sign & verify")

    # Test 4: alg none
    token_none = sign_hmac({"alg": "none"}, {"sub": "unsecured"}, "", "none")
    assert_true(token_none.endswith("."), "alg none ends with trailing dot")
    assert_true(verify_hmac(token_none, "", "none"), "alg none verification")

    # Test 5: Claims validation
    now = time.time()
    claims_valid = validate_claims({"exp": now + 3600, "nbf": now - 10}, leeway=5)
    assert_true(claims_valid["claims_valid"] is True, "Valid claims pass validation")

    claims_expired = validate_claims({"exp": now - 3600})
    assert_true(claims_expired["claims_valid"] is False and claims_expired["is_expired"], "Expired claims fail validation")

    # Test 6: Security Audit - CVE-2015-9235 Detection
    audit_none = audit_jwt_security(token_none)
    has_cve_none = any(f["id"] == "CVE_2015_9235_NONE_ALGORITHM" for f in audit_none["findings"])
    assert_true(has_cve_none, "Security audit catches CVE-2015-9235 (alg: none)")
    assert_true(audit_none["score"] <= 50, "Unsigned token receives low risk score")

    # Test 7: Security Audit - Weak Secret & Cracking
    weak_token = sign_hmac({"alg": "HS256"}, {"sub": "weak"}, "password123", "HS256")
    crack_res = crack_jwt_secret(weak_token)
    assert_true(crack_res["cracked"] and crack_res["secret"] == "password123", "Secret dictionary attack cracks weak key")

    # Test 8: MCP Protocol Handshake
    init_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert_true(isinstance(init_resp, dict) and init_resp.get("result", {}).get("serverInfo", {}).get("name") == SERVER_NAME, "MCP initialize handshake")

    tools_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_list = tools_resp.get("result", {}).get("tools", [])
    assert_true(len(tools_list) >= 7, f"MCP tools/list registers all tools (found {len(tools_list)})")

    call_resp = handle_jsonrpc_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "jwt_decode",
            "arguments": {"token": token_hs256}
        }
    })
    assert_true(not call_resp.get("result", {}).get("isError"), "MCP tools/call jwt_decode succeeds")

    print()
    print(f"Test Summary: {c_str(f'{passed} Passed', GREEN)}, {c_str(f'{failed} Failed', RED if failed else GREEN)}")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# CLI Main Dispatcher with Flexible Flag Handling
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build root and subparser command hierarchy with parent parser inheritance."""
    # Parent parser for global options
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colored output")
    parent_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and decorative headers")
    parent_parser.add_argument("-v", "--version", action="store_true", help="Display version and exit")

    root_parser = argparse.ArgumentParser(
        prog="jwt-guard",
        description="JWT Inspector Guard: Multi-OS MCP Server, CLI & Security Auditor for JSON Web Tokens",
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = root_parser.add_subparsers(dest="subcommand", title="Subcommands", help="Available actions")

    # 1. decode
    p_decode = subparsers.add_parser("decode", parents=[parent_parser], help="Decode and display colored 3-part token breakdown")
    p_decode.add_argument("token", nargs="?", help="Compact JWT string (or '-' / omitted for stdin)")
    p_decode.add_argument("--json", action="store_true", help="Output raw JSON representation")
    p_decode.set_defaults(func=cmd_decode)

    # 2. verify
    p_verify = subparsers.add_parser("verify", parents=[parent_parser], help="Verify signature and validate claims")
    p_verify.add_argument("token", nargs="?", help="Compact JWT string (or '-' / omitted for stdin)")
    p_verify.add_argument("-s", "--secret", help="HMAC secret key")
    p_verify.add_argument("-a", "--alg", help="Expected algorithm (HS256, HS384, HS512, none)")
    p_verify.add_argument("--iss", "--issuer", dest="iss", help="Expected issuer claim")
    p_verify.add_argument("--aud", "--audience", dest="aud", help="Expected audience claim")
    p_verify.add_argument("--leeway", type=float, default=0.0, help="Clock skew leeway in seconds")
    p_verify.add_argument("--json", action="store_true", help="Output JSON verification report")
    p_verify.set_defaults(func=cmd_verify)

    # 3. encode
    p_encode = subparsers.add_parser("encode", parents=[parent_parser], help="Mint and sign a new JWT token")
    p_encode.add_argument("-p", "--payload", help="JSON payload string, file path, or '-' for stdin")
    p_encode.add_argument("-s", "--secret", default="", help="Signing secret key")
    p_encode.add_argument("-a", "--alg", default="HS256", help="Algorithm (HS256, HS384, HS512, none)")
    p_encode.add_argument("--exp", help="Expiration in seconds from now (e.g. 3600) or absolute timestamp")
    p_encode.add_argument("--sub", help="Subject claim ('sub')")
    p_encode.add_argument("--iss", help="Issuer claim ('iss')")
    p_encode.add_argument("--aud", help="Audience claim ('aud')")
    p_encode.add_argument("--header", help="Custom header JSON string")
    p_encode.add_argument("--json", action="store_true", help="Output JSON object containing token and claims")
    p_encode.set_defaults(func=cmd_encode)

    # 4. audit
    p_audit = subparsers.add_parser("audit", parents=[parent_parser], help="Run comprehensive security audit & scorecard")
    p_audit.add_argument("token", nargs="?", help="Compact JWT string (or '-' / omitted for stdin)")
    p_audit.add_argument("-s", "--secret", help="Optional known secret key to verify")
    p_audit.add_argument("--json", action="store_true", help="Output JSON audit report")
    p_audit.set_defaults(func=cmd_audit)

    # 5. crack
    p_crack = subparsers.add_parser("crack", parents=[parent_parser], help="Dictionary attack weak HMAC secrets")
    p_crack.add_argument("token", nargs="?", help="Compact JWT string (or '-' / omitted for stdin)")
    p_crack.add_argument("-w", "--wordlist", help="Path to custom wordlist file")
    p_crack.add_argument("--max-attempts", type=int, default=5000, help="Maximum secret candidates to test")
    p_crack.add_argument("--json", action="store_true", help="Output JSON crack report")
    p_crack.set_defaults(func=cmd_crack)

    # 6. samples
    p_samples = subparsers.add_parser("samples", parents=[parent_parser], help="List built-in sample JWTs and CVE vectors")
    p_samples.add_argument("-c", "--category", default="all", help="Category filter: all, standard, vulnerabilities, attacks, oauth2")
    p_samples.add_argument("-g", "--get", help="Print token string for specific sample name")
    p_samples.add_argument("--json", action="store_true", help="Output JSON catalog")
    p_samples.set_defaults(func=cmd_samples)

    # 7. serve
    p_serve = subparsers.add_parser("serve", parents=[parent_parser], help="Launch Material 3 JWT Studio Web UI & REST API")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    p_serve.add_argument("-p", "--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p_serve.add_argument("--open", action="store_true", default=True, help="Automatically open browser")
    p_serve.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    p_serve.set_defaults(func=cmd_serve)

    # 8. mcp
    p_mcp = subparsers.add_parser("mcp", parents=[parent_parser], help="Run MCP stdio protocol server")
    p_mcp.set_defaults(func=cmd_mcp)

    # 9. diagnostics / doctor / platform
    for alias in ["diagnostics", "doctor", "platform"]:
        p_diag = subparsers.add_parser(alias, parents=[parent_parser], help="Display platform and crypto diagnostics")
        p_diag.add_argument("--json", action="store_true", help="Output JSON diagnostic report")
        p_diag.set_defaults(func=cmd_diagnostics)

    # 10. test
    p_test = subparsers.add_parser("test", parents=[parent_parser], help="Run internal self-verification test runner")
    p_test.set_defaults(func=cmd_test)

    return root_parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Main Entry Point."""
    if argv is None:
        argv = sys.argv[1:]

    # Early check for global flags before parse
    if "--no-color" in argv:
        configure_color(force_no_color=True)
    else:
        configure_color(force_no_color=False)

    if "-v" in argv or "--version" in argv:
        print(f"jwt-inspector-guard v{SERVER_VERSION} (MCP Protocol {PROTOCOL_VERSION})")
        return 0

    parser = build_parser()

    if not argv:
        print_banner(quiet=False)
        print()
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        print(f"jwt-inspector-guard v{SERVER_VERSION} (MCP Protocol {PROTOCOL_VERSION})")
        return 0

    if getattr(args, "no_color", False):
        configure_color(force_no_color=True)

    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
