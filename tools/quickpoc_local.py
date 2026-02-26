#!/usr/bin/env python3
"""Local QuickPoC runner for client-side prototype-pollution PoC.

Usage:
  python3 tools/quickpoc_local.py --target https://example.com --headless

This script attempts to initialize a Chrome webdriver via webdriver-manager
and execute non-destructive `$.extend` payloads in the page context.
It writes a JSON report to ./reports/quickpoc_{timestamp}.json.

NOTE: Run this on your local machine where Chrome/Chromium and matching
ChromeDriver are available. If you get a ChromeDriver version mismatch,
update ChromeDriver or install a matching Chrome/Chromium version.
"""

import argparse
import json
import os
from datetime import datetime

from ppmap.reports import EnhancedReportGenerator
from ppmap.scanner import QuickPoC

try:
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False


def main():
    p = argparse.ArgumentParser(description="Local QuickPoC runner (non-destructive)")
    p.add_argument("--target", required=True, help="Target URL to run QuickPoC against")
    p.add_argument(
        "--headless", action="store_true", default=False, help="Run browser headless"
    )
    p.add_argument("--output", default="./reports", help="Output directory for reports")
    p.add_argument("--timeout", type=int, default=15, help="Page load timeout seconds")
    args = p.parse_args()

    target = args.target
    headless = args.headless

    print(f"[+] QuickPoC local runner\nTarget: {target}\nHeadless: {headless}")

    results = []

    # First try Selenium-based QuickPoC
    qp = QuickPoC(headless=headless)
    ok = False
    try:
        ok = qp.setup_browser(target)
    except Exception:
        ok = False

    if ok:
        try:
            safe_payloads = [
                {"__proto__": {"ppmap_test": "pp_local"}},
                {"constructor": {"prototype": {"ppmap_test": "pp_local"}}},
            ]
            for payload in safe_payloads:
                try:
                    executed = qp.test_payload(payload)
                    results.append({"payload": payload, "executed": bool(executed)})
                    print(f"  - payload executed: {bool(executed)} payload={payload}")
                except Exception as e:
                    results.append(
                        {"payload": payload, "executed": False, "error": str(e)}
                    )
                    print(f"  - payload error: {e}")
        finally:
            qp.cleanup()
    else:
        print(
            "[!] Selenium QuickPoC not available or failed to start; trying Playwright fallback"
        )
        # Playwright fallback (preferred for reproducible local runs)
        if not PLAYWRIGHT_AVAILABLE:
            print(
                "[!] Playwright not installed; please pip install playwright and run `playwright install`"
            )
        else:
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=headless)
                    page = browser.new_page()
                    page.set_default_navigation_timeout(args.timeout * 1000)
                    page.goto(target)

                    safe_payloads = [
                        {"__proto__": {"ppmap_test": "pp_local"}},
                        {"constructor": {"prototype": {"ppmap_test": "pp_local"}}},
                    ]
                    for payload in safe_payloads:
                        try:
                            # execute $.extend if jQuery present
                            executed = page.evaluate(
                                "(payload) => { try { if(window.jQuery){ window.jQuery.extend(true, {}, payload); return true;} return false;} ",
                                payload,
                            )
                            results.append(
                                {"payload": payload, "executed": bool(executed)}
                            )
                            print(
                                f"  - playwright payload executed: {bool(executed)} payload={payload}"
                            )
                        except Exception as e:
                            results.append(
                                {"payload": payload, "executed": False, "error": str(e)}
                            )
                            print(f"  - playwright payload error: {e}")
                    browser.close()
            except Exception as e:
                print(f"[!] Playwright run failed: {e}")

    # write report
    EnhancedReportGenerator(output_dir=args.output)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = {"target": target, "timestamp": timestamp, "results": results}
    fp = os.path.join(args.output, f"quickpoc_{timestamp}.json")
    os.makedirs(args.output, exist_ok=True)
    with open(fp, "w") as fh:
        json.dump(out, fh, indent=2)

    print(f"[+] QuickPoC results saved to {fp}")


if __name__ == "__main__":
    main()
