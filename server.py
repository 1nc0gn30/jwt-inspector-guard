#!/usr/bin/env python3
"""
JWT Inspector Guard v2.6.0 - Sovereign Standalone Web & REST Server
Listens on http://127.0.0.1:8124 by default.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from jwt_inspector_guard.ui_server import run_server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwt-inspector-guard-server",
        description="JWT Inspector Guard v2.6.0 loopback Web UI and REST API server.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Loopback bind host (default: 127.0.0.1 or $HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", os.environ.get("JWT_GUARD_PORT", "8124"))),
        help="Loopback listen port (default: 8124 or $PORT)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        default=False,
        help="Open the UI in the default browser after startup",
    )
    args = parser.parse_args(argv)
    print(f"Starting JWT Inspector Guard v2.6.0 on http://{args.host}:{args.port} ...")
    run_server(host=args.host, port=args.port, open_browser=args.open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
