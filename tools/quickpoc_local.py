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
import logging
import sys
from datetime import datetime
from urllib.parse import urlparse

from ppmap.reports import EnhancedReportGenerator
from ppmap.engine import QuickPoC

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# PLAYWRIGHT FALLBACK
# ============================================================================

try:
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception as e:
    logger.warning(f"Playwright not available: {e}")
    PLAYWRIGHT_AVAILABLE = False


def validate_url(url: str) -> bool:
    """
    Validate URL format to prevent issues during browser load.

    Args:
        url: URL to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        res = urlparse(url)
        if not res.scheme or res.scheme not in ["http", "https"]:
            logger.error("URL must include valid scheme (http/https)")
            return False
        if not res.netloc:
            logger.error("URL must include domain")
            return False
        return True
    except Exception as e:
        logger.error(f"Invalid URL: {e}")
        return False


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

    # SECURITY: Validate URL format before proceeding
    if not validate_url(target):
        sys.exit(1)

    logger.info(f"QuickPoC local runner\nTarget: {target}\nHeadless: {headless}")

    results = []

    # First try Selenium-based QuickPoC
    qp = QuickPoC(headless=headless)
    ok = False
    try:
        ok = qp.setup_browser(target)
        logger.info("Selenium QuickPoC initialized")
    except Exception as e:
        logger.error(f"Failed to setup Selenium browser: {e}")
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
                    logger.info(
                        f"  - payload executed: {bool(executed)} payload={payload}"
                    )
                except Exception as e:
                    results.append(
                        {"payload": payload, "executed": False, "error": str(e)}
                    )
                    logger.error(f"  - payload error: {e}")
        finally:
            qp.cleanup()
    else:
        logger.warning(
            "Selenium QuickPoC not available or failed to start; trying Playwright fallback"
        )
        # Playwright fallback (preferred for reproducible local runs)
        if not PLAYWRIGHT_AVAILABLE:
            logger.error(
                "Playwright not installed; please pip install playwright and run `playwright install`"
            )
        else:
            try:
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(headless=headless)
                    page = browser.new_page()
                    page.set_default_navigation_timeout(args.timeout * 1000)

                    try:
                        page.goto(target)
                        logger.info(f"Successfully loaded {target}")
                    except Exception as e:
                        logger.error(f"Failed to load target: {e}")
                        browser.close()
                        return

                    safe_payloads = [
                        {"__proto__": {"ppmap_test": "pp_local"}},
                        {"constructor": {"prototype": {"ppmap_test": "pp_local"}}},
                    ]
                    for payload in safe_payloads:
                        try:
                            # execute $.extend if jQuery present. Fixed JS block.
                            executed = page.evaluate(
                                """(payload) => { 
                                    try { 
                                        if(window.jQuery){ 
                                            window.jQuery.extend(true, {}, payload); 
                                            return true;
                                        } 
                                        return false;
                                    } catch(e) {
                                        console.error('Error:', e);
                                        return false;
                                    }
                                }""",
                                payload,
                            )
                            results.append(
                                {"payload": payload, "executed": bool(executed)}
                            )
                            logger.info(
                                f"  - playwright payload executed: {bool(executed)} payload={payload}"
                            )
                        except Exception as e:
                            results.append(
                                {"payload": payload, "executed": False, "error": str(e)}
                            )
                            logger.error(f"  - playwright payload error: {e}")
                    browser.close()
            except Exception as e:
                logger.error(f"Playwright run failed: {e}")

    # write report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = {"target": target, "timestamp": timestamp, "results": results}

    try:
        os.makedirs(args.output, exist_ok=True)
        fp = os.path.join(args.output, f"quickpoc_{timestamp}.json")
        with open(fp, "w") as fh:
            json.dump(out, fh, indent=2)
        logger.info(f"QuickPoC results saved to {fp}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")


if __name__ == "__main__":
    main()
