#!/usr/bin/env python3
"""
JWT Inspector Guard - Sovereign Standalone Web & REST Server
Listens on http://127.0.0.1:8124 by default.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from jwt_inspector_guard.ui_server import run_server

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8124))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"⚡ Starting JWT Inspector Guard on http://{host}:{port} ...")
    run_server(host=host, port=port, open_browser=False)
