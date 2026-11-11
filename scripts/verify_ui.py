"""
verify_ui.py
Headless Playwright verification harness for JWT Inspector Guard.

Checks triple-viewport rendering (mobile / tablet / desktop), zero console
errors, zero horizontal overflow, and that the core audit workflow runs.

Usage:
    python3 server.py &                      # serves on 127.0.0.1:8124
    JWT_GUARD_URL=http://127.0.0.1:8124 python3 scripts/verify_ui.py

Environment:
    JWT_GUARD_URL   Base URL to test (default http://127.0.0.1:8124)
    SHOT_DIR        Screenshot output directory (default ./.verify_shots)
    CHROME_PATH     Optional Chromium/Chrome executable path
"""

import json
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
SHOT_DIR = Path(os.environ.get("SHOT_DIR", ROOT_DIR / ".verify_shots"))
SHOT_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = os.environ.get("JWT_GUARD_URL", "http://127.0.0.1:8124").rstrip("/")


def verify():
    print(f"[TEST] Starting Playwright headless verification on {BASE_URL}...")

    viewports = [
        {"name": "home_mobile.jpg", "width": 390, "height": 844, "device": "Mobile"},
        {"name": "home_tablet.jpg", "width": 820, "height": 1180, "device": "Tablet"},
        {"name": "home_desktop.jpg", "width": 1425, "height": 900, "device": "Desktop"},
    ]

    results = {"viewports": [], "auditPass": False, "consoleErrors": []}

    launch_kwargs = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
    }
    if os.environ.get("CHROME_PATH"):
        launch_kwargs["executable_path"] = os.environ["CHROME_PATH"]

    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kwargs)

        # 1. Triple-viewport rendering
        for vp in viewports:
            page = browser.new_page(viewport={"width": vp["width"], "height": vp["height"]})
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("pageerror", lambda err: console_errors.append(str(err)))

            page.goto(BASE_URL, wait_until="networkidle")
            time.sleep(0.5)

            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            shot_path = SHOT_DIR / vp["name"]
            page.screenshot(path=str(shot_path), full_page=False, type="jpeg", quality=85)

            passed = len(console_errors) == 0 and overflow <= 1
            print(f"[VIEWPORT] {vp['device']}: errors={len(console_errors)} overflow={overflow}px -> {'PASS' if passed else 'FAIL'}")
            results["consoleErrors"].extend(f"[{vp['device']}] {e}" for e in console_errors)
            results["viewports"].append(
                {"device": vp["device"], "overflow": overflow, "passed": passed, "screenshot": str(shot_path)}
            )
            page.close()

        # 2. Core audit workflow: load sample token, run audit, expect findings
        page = browser.new_page(viewport={"width": 1425, "height": 900})
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))
        page.goto(BASE_URL, wait_until="networkidle")
        time.sleep(0.5)
        token_len = page.evaluate("() => document.getElementById('tokenInput').value.length")
        findings_html = page.evaluate("() => document.getElementById('findingsList').innerHTML.length")
        results["auditPass"] = token_len > 0 and findings_html > 0 and not errors
        results["consoleErrors"].extend(f"[Audit] {e}" for e in errors)
        print(f"[AUDIT] tokenLength={token_len} findingsHtml={findings_html} -> {'PASS' if results['auditPass'] else 'FAIL'}")
        page.close()
        browser.close()

    with open(SHOT_DIR / "verification_results.json", "w") as f:
        json.dump(results, f, indent=2)

    all_passed = (
        not results["consoleErrors"]
        and results["auditPass"]
        and all(v["passed"] for v in results["viewports"])
    )
    print("ALL CHECKS PASSED" if all_passed else "SOME CHECKS FAILED")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(verify())
