#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.4.2 Enterprise (Scanner | Browser | 0-Day | OOB)

DISCLAIMER:
===========
This tool is designed for authorized security testing and educational purposes ONLY.
Unauthorized access to computer systems is illegal. The author assumes NO liability
for misuse or damage caused by this tool. Users are responsible for ensuring they
have explicit permission to test the target systems. Failure to obtain proper
authorization is a violation of computer fraud and abuse laws.

USE AT YOUR OWN RISK - AUTHOR NOT LIABLE FOR ANY DAMAGES
"""

import sys
import time
import json
import os
import argparse
import urllib.parse
import re
import logging
import random
import warnings
from html import escape as html_escape
from datetime import datetime
from typing import Dict, List, Optional, Any
import traceback
from enum import Enum
from dataclasses import dataclass, asdict, field
from ppmap.utils import normalize_url

from ppmap.browser import get_browser
from ppmap.models.findings import Severity, VulnerabilityType, Finding
from ppmap.models.reports import ScanMetrics, ScanReport
from ppmap.config.settings import CONFIG, STEALTH_HEADERS
from ppmap.config import load as load_config
from ppmap.scanner.core import (
    CompleteSecurityScanner,
    safe_execute,
    progress_iter,
    Colors,
)
from ppmap.utils.update_checker import check_for_updates
from ppmap.utils.burp_parser import parse_burp_request
from ppmap.utils.cookie_parser import load_cookies_to_headers
from ppmap.__init__ import __version__

# Progress bar
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


# ============================================================================
# ============================================================================
# ASYNC SCANNER ENGINE
# ============================================================================
# AsyncScanner moved to ppmap.scanner

# Use modular report generator and centralized logging
try:
    from ppmap.reports import EnhancedReportGenerator
    from ppmap.log_setup import setup_logging
    from ppmap.browser import get_browser
except Exception:
    EnhancedReportGenerator = None

    def setup_logging(*args, **kwargs):
        return logging.getLogger()

    get_browser = None

# Logging is configured via ppmap.logging.setup_logging

# Initialize logger
logger = logging.getLogger(__name__)

# ============================================================================
# SUPPRESS URLLIB3 WARNINGS (For unverified HTTPS - pentest tool)
# ============================================================================
try:
    from urllib3.exceptions import InsecureRequestWarning

    # Suppress InsecureRequestWarning for self-signed certificates
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    urllib3_logger = logging.getLogger("urllib3.connectionpool")
    urllib3_logger.setLevel(logging.ERROR)
except ImportError:
    pass

# ============================================================================


# ============================================================================
# PRINT BANNER & DISCLAIMER
# ============================================================================
def print_banner():
    banner = (
        Colors.BOLD
        + Colors.CYAN
        + r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.4.2 Enterprise (Scanner | Browser | 0-Day | OOB)
"""
        + Colors.ENDC
        + f"""

{Colors.WARNING}⚠️  DISCLAIMER:{Colors.ENDC}
This tool is for AUTHORIZED SECURITY TESTING ONLY.
Unauthorized access to systems is ILLEGAL.
Author assumes NO liability for misuse or damages.
Use only with explicit permission on target systems.

{Colors.GREEN}Run with -h for help, --poc for quick PoC, --scan for full scan{Colors.ENDC}
"""
    )
    print(banner)


# ============================================================================
# QUICK POC MODE
# ============================================================================
def run_quick_poc(url: str, headless: bool = True) -> None:
    """Run a fast non-destructive jQuery Prototype Pollution PoC on the target.

    Uses the QuickPoC class from ppmap.engine which tries Selenium first and
    falls back to Playwright if Selenium is unavailable.
    """
    from ppmap.engine import QuickPoC
    from ppmap.payloads import QUICK_POC_PAYLOADS

    print(f"{Colors.BOLD}[*] Quick PoC mode on {url}{Colors.ENDC}")

    poc = QuickPoC(headless=headless)
    ready = False
    try:
        print(f"{Colors.BLUE}[*] Setting up browser...{Colors.ENDC}")
        ready = poc.setup_browser(url)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Browser setup failed: {e}{Colors.ENDC}")
        logger.error(f"Browser setup failed: {e}", exc_info=True)

    if not ready:
        print(
            f"{Colors.WARNING}[!] Browser not available — cannot run client-side PoC.{Colors.ENDC}\n"
            f"    Try installing Playwright:  pip install playwright && playwright install chromium"
        )
        return

    confirmed = False
    try:
        print(f"{Colors.BLUE}[*] Testing {len(QUICK_POC_PAYLOADS)} payloads...{Colors.ENDC}")
        for i, p in enumerate(QUICK_POC_PAYLOADS):
            try:
                print(f"{Colors.BLUE}[→] Testing payload #{i+1}...{Colors.ENDC}")
                if poc.test_payload(p):
                    print(
                        f"{Colors.FAIL}[!] CONFIRMED: Prototype Pollution detected!\n"
                        f"    Payload: {p}{Colors.ENDC}"
                    )
                    confirmed = True
                    break
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error testing payload: {e}{Colors.ENDC}")
                logger.debug(f"QuickPoC payload error: {e}", exc_info=True)
    finally:
        print(f"{Colors.BLUE}[*] Cleaning up...{Colors.ENDC}")
        poc.cleanup()

    if not confirmed:
        print(f"{Colors.GREEN}[✓] No Prototype Pollution detected via Quick PoC.{Colors.ENDC}")


try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import (
        TimeoutException,
        WebDriverException,
        NoSuchElementException,
        StaleElementReferenceException,
        InvalidSessionIdException,
    )

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print(
        f"{Colors.WARNING}[!] Selenium not available. Install: pip install selenium{Colors.ENDC}"
    )
    logger.error("Selenium not installed")

try:
    import requests
    from bs4 import BeautifulSoup
    import urllib.parse as urlparse

    # Suppress SSL warnings for unverified HTTPS (pentest context)
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print(f"{Colors.FAIL}[!] Error: requests & beautifulsoup4 required.{Colors.ENDC}")
    sys.exit(1)

# Load configuration from consolidated module
try:
    from ppmap.config import load as load_config

    PPMAP_CONFIG = load_config()
except Exception:
    # Fallback to minimal defaults
    PPMAP_CONFIG = {
        "scanning": {"timeout": 15, "max_workers": 3},
        "reporting": {"format": ["json", "html"], "output_dir": "./reports"},
    }


def main():
    # Setup logging first
    log_level = logging.DEBUG if os.getenv("PPMAP_DEBUG") else logging.INFO
    setup_logging(log_level)

    print_banner()
    logger.info("PPMAP started")

    # Check for updates in a non-blocking way
    check_for_updates(__version__)

    parser = argparse.ArgumentParser(
        description="PPMAP v4.4.2 - Prototype Pollution Assessment Platform (Enterprise Edition)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
SCANNING MODES:
  Quick PoC:
    python ppmap.py --poc http://target.com
  
  Full Scan (Discovery + Attack):
    python ppmap.py --scan-full http://target.com

  Scan Specific URLs (No Crawl):
    python ppmap.py --scan http://target.com/page1 http://target.com/page2
  
  Multiple targets:
    python ppmap.py --scan http://target1.com http://target2.com
  
  Discovery Only (Recon):
    python ppmap.py --discover http://target.com --max-depth 2
  
  With stealth mode:
    python ppmap.py --scan http://target.com --stealth --delay 1
  
  Custom configuration:
    python ppmap.py --scan http://target.com --config custom.yaml

ADVANCED OPTIONS:
  Rate limiting:
    python ppmap.py --scan http://target.com --rate-limit 30
  
  Custom output:
    python ppmap.py --scan http://target.com --output ./my_reports --format json,html,markdown
  
  Verbose logging:
    PPMAP_DEBUG=1 python ppmap.py --scan http://target.com
        """,
    )

    # Core arguments
    parser.add_argument(
        "--poc", type=str, metavar="URL", help="Run Quick PoC mode on target"
    )
    parser.add_argument(
        "--quickpoc-local",
        type=str,
        metavar="URL",
        help="Run local QuickPoC (uses Playwright/Selenium fallback)",
    )
    parser.add_argument(
        "--scan", nargs="*", metavar="URL", help="Scan provided URL(s) without automatic discovery"
    )
    parser.add_argument(
        "--scan-full", nargs="*", metavar="URL", help="Full Scan mode (Discovery + Attack) on target(s)"
    )
    parser.add_argument(
        "--discover", nargs="*", metavar="URL", help="Recon only: discover endpoints and parameters without attacking"
    )
    parser.add_argument(
        "-ls",
        "--list",
        type=str,
        metavar="FILE",
        help="Read target URLs from file (one URL per line)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read target URLs from stdin (for pipeline: subfinder | httpx | ppmap --scan --stdin)",
    )
    parser.add_argument(
        "--request",
        "-r",
        type=str,
        metavar="FILE",
        help="Scan from Burp Suite request file (authenticated scan)",
    )
    parser.add_argument(
        "--cookies",
        type=str,
        metavar="FILE",
        help="Load cookies from JSON file (authenticated scan)",
    )

    # Configuration
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Config file (default: config.yaml)",
    )

    # Browser options
    parser.add_argument(
        "--browser",
        type=str,
        default="chrome",
        choices=["chrome", "firefox"],
        help="Browser to use (chrome|firefox)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per request in seconds (default: 30)",
    )
    parser.add_argument(
        "--workers", type=int, default=3, help="Max concurrent workers (default: 3)"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Headless browser (default: True)",
    )
    parser.add_argument(
        "--no-headless",
        dest="headless",
        action="store_false",
        help="Show browser window",
    )

    # Stealth & Rate Limiting
    parser.add_argument(
        "--stealth", action="store_true", help="Enable stealth mode (anti-detection)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, help="Delay between requests in seconds"
    )
    parser.add_argument(
        "--rate-limit", type=int, metavar="N", help="Requests per minute limit"
    )
    parser.add_argument("--user-agent", type=str, help="Custom User-Agent")

    # Feature toggles
    parser.add_argument(
        "--disable-jquery-pp", action="store_true", help="Disable jQuery PP tests"
    )
    parser.add_argument("--disable-xss", action="store_true", help="Disable XSS tests")
    parser.add_argument(
        "--disable-waf-bypass",
        action="store_true",
        help="Disable WAF bypass tests",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable detailed debug logging",
    )
    
    # --- PHASE 8 CRAWLER OPTIONS ---
    parser.add_argument(
        "--no-crawl", 
        action="store_true", 
        help="Disable endpoint crawler (when using --scan-full)"
    )
    parser.add_argument(
        "--max-endpoints", 
        type=int, 
        default=30, 
        help="Max hidden endpoints to discover per target (default: 30)"
    )
    parser.add_argument(
        "--max-depth", 
        type=int, 
        default=1, 
        help="Crawl depth for discovery (default: 1)"
    )
    parser.add_argument(
        "--max-urls", 
        type=int, 
        default=100, 
        help="Max unique URLs to scan in total (default: 100)"
    )

    parser.add_argument(
        "--disable-discovery", action="store_true", help="Disable endpoint discovery"
    )

    # Reporting
    parser.add_argument(
        "--output",
        type=str,
        default="./reports",
        help="Output directory (default: ./reports)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="json,html,csv,xml,md",
        help="Report formats (json,html,markdown,jupyter,csv,xml,md,pdf)",
    )
    parser.add_argument(
        "--template",
        type=str,
        default="modern",
        help="Report template (modern, minimal, detailed)",
    )
    parser.add_argument(
        "--no-poc", action="store_true", help="Don't include PoC in reports"
    )
    parser.add_argument(
        "--async-scan",
        action="store_true",
        help="Enable async scanning engine (EXPERIMENTAL)",
    )
    parser.add_argument(
        "--async-workers",
        type=int,
        default=10,
        help="Max async concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--oob",
        action="store_true",
        help="Enable OOB/Blind detection (Uses Interact.sh)",
    )

    # Additional options
    parser.add_argument(
        "--verify-ssl", action="store_true", help="Verify SSL certificates"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification (insecure)",
    )
    parser.add_argument(
        "--proxy", type=str, metavar="PROXY", help="HTTP proxy (http://proxy:port)"
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("FILE1", "FILE2"),
        help="Compare two scan result files",
    )
    parser.add_argument(
        "--preset",
        choices=["quick", "thorough", "stealth"],
        help="Use configuration preset (overrides defaults)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Verbose output (-v, -vv, -vvv)",
    )
    parser.add_argument("--version", action="version", version="PPMAP v4.4.2")

    # Argument completion
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    # Apply debug logging if requested
    if args.debug:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)

    # Apply presets if specified
    if args.preset:
        if args.preset == "quick":
            print(f"{Colors.BLUE}[*] Applying 'QUICK' preset{Colors.ENDC}")
            args.workers = 1
            args.headless = True
            args.disable_waf_bypass = True
            args.oob = False
        elif args.preset == "thorough":
            print(f"{Colors.BLUE}[*] Applying 'THOROUGH' preset{Colors.ENDC}")
            args.workers = 10
            args.oob = True
            args.verify_ssl = False
        elif args.preset == "stealth":
            print(f"{Colors.BLUE}[*] Applying 'STEALTH' preset{Colors.ENDC}")
            args.workers = 2
            args.delay = 2.0
            args.rate_limit = 5
            args.stealth = True
            args.headless = True

    # Handle Diff Mode
    if args.diff:
        from tools.analyze_scan_results import diff_scan_results

        try:
            diff_scan_results(args.diff[0], args.diff[1])
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error running diff: {e}{Colors.ENDC}")
        sys.exit(0)
    if args.config and os.path.exists(args.config):

        try:
            from ppmap.config import load as load_config_fallback

            config = load_config_fallback(args.config)
        except Exception:
            try:
                # older version compatibility if any
                config = load_config(args.config)
            except NameError:
                print("[!] Failed to load custom config. Using defaults.")
                config = {}

        PPMAP_CONFIG.update(config)
        logger.info(f"Loaded configuration from {args.config}")

    # Update config from CLI arguments (overrides file config)
    if args.timeout:
        PPMAP_CONFIG["scanning"]["timeout"] = args.timeout
    if args.workers:
        PPMAP_CONFIG["scanning"]["max_workers"] = args.workers
    if args.stealth:
        PPMAP_CONFIG["scanning"]["stealth_mode"] = True
    if args.verify_ssl:
        PPMAP_CONFIG["scanning"]["disable_ssl_verify"] = False
    if args.insecure:
        PPMAP_CONFIG["scanning"]["disable_ssl_verify"] = True
    if args.rate_limit:
        PPMAP_CONFIG["rate_limiting"]["enabled"] = True
        PPMAP_CONFIG["rate_limiting"]["requests_per_minute"] = args.rate_limit

    # Feature toggles
    if args.disable_jquery_pp:
        PPMAP_CONFIG["testing"]["jquery_pp"] = False
    if args.disable_xss:
        PPMAP_CONFIG["testing"]["xss"] = False
    if args.disable_waf_bypass:
        PPMAP_CONFIG["testing"]["waf_bypass"] = False

    # Reporting
    if args.format:
        # Split by comma if multiple formats
        PPMAP_CONFIG["reporting"]["format"] = args.format.split(",")
    if args.output:
        PPMAP_CONFIG["reporting"]["output_dir"] = args.output
    if args.disable_discovery:
        PPMAP_CONFIG["testing"]["endpoint_discovery"] = False

    # Reporting config handled above
    # PPMAP_CONFIG['reporting']['template'] = args.template
    if args.template:
        PPMAP_CONFIG["reporting"]["template"] = args.template
    PPMAP_CONFIG["reporting"]["include_poc"] = not args.no_poc

    # Async config
    PPMAP_CONFIG["async"] = {
        "enabled": args.async_scan,
        "max_concurrent": args.async_workers,
        "timeout": args.timeout or 30,
    }

    # Logging verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logger.setLevel(logging.INFO)

    logger.debug(f"Configuration: {PPMAP_CONFIG}")

    # Handle cookies from JSON file
    auth_headers = {}
    if args.cookies:
        try:
            print(f"{Colors.BLUE}[*] Loading cookies from: {args.cookies}{Colors.ENDC}")
            auth_headers = load_cookies_to_headers(args.cookies, auth_headers)
            print(f"{Colors.GREEN}[✓] Cookies loaded successfully{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error loading cookies: {e}{Colors.ENDC}")
            logger.error(f"Cookie loading error: {e}")

    # Handle scan from request file
    if args.request:
        if not parse_burp_request:
            logger.error("Burp parser module not found")
            return

        try:
            print(f"{Colors.BLUE}[*] Parsing request file: {args.request}{Colors.ENDC}")
            req_data = parse_burp_request(args.request)
            target_url = req_data["url"]

            print(f"{Colors.BLUE}[*] Target URL: {target_url}{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Method: {req_data['method']}{Colors.ENDC}")

            from ppmap.service.scan_service import run_scan
            from ppmap.models.config import ScanConfig

            # Setup auth tracking early so we can reuse
            auth_headers = req_data.get("headers", {})
            if auth_headers:
                print(
                    f"{Colors.GREEN}[✓] Loaded {len(auth_headers)} headers (cookies included){Colors.ENDC}"
                )

            # Special handling for POST requests (often SSPP)
            if req_data["method"] == "POST" and req_data.get("body"):
                print(
                    f"{Colors.BLUE}[*] Detected POST body - Prioritizing Server-Side PP checks{Colors.ENDC}"
                )

            # Initialize scan configuration
            scan_config = ScanConfig(
                timeout=args.timeout,
                max_workers=args.workers,
                stealth=PPMAP_CONFIG["scanning"].get("stealth_mode", False),
                verify_ssl=not PPMAP_CONFIG["scanning"].get("disable_ssl_verify", False),
                rate_limit=PPMAP_CONFIG["rate_limiting"].get("requests_per_minute", 60) if PPMAP_CONFIG["rate_limiting"].get("enabled") else None,
                delay=args.delay
            )

            # Initialize custom headers list in config
            if auth_headers:
                scan_config.custom_headers = auth_headers

            # Continue with full scan on the URL, passing request data
            # Use the new scan_service
            session = run_scan(
                target_url=target_url,
                config=scan_config,
                request_data=req_data,
                run_discovery=False
            )

        except Exception as e:
            logger.error(f"Error processing request file: {e}")
            traceback.print_exc()
        return

    # --- TARGET LOADING & DISCOVERY PHASE ---
    targets = []
    if args.scan:
        targets.extend(args.scan)
    if args.scan_full:
        targets.extend(args.scan_full)
    if args.discover:
        targets.extend(args.discover)
    
    if args.list:
        try:
            with open(args.list, "r") as f:
                file_targets = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                targets.extend(file_targets)
                logger.info(f"Loaded {len(file_targets)} target(s) from {args.list}")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Error: File '{args.list}' not found{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
            sys.exit(1)

    if args.stdin:
        if not sys.stdin.isatty():
            stdin_targets = [
                line.strip()
                for line in sys.stdin
                if line.strip() and not line.startswith("#")
            ]
            targets.extend(stdin_targets)
            logger.info(f"Loaded {len(stdin_targets)} target(s) from stdin")
        else:
            print(f"{Colors.WARNING}[!] No pipe detected. Enter URLs (one per line, Ctrl+D to finish):{Colors.ENDC}")
            stdin_targets = [
                line.strip()
                for line in sys.stdin
                if line.strip() and not line.startswith("#")
            ]
            targets.extend(stdin_targets)
            if stdin_targets:
                logger.info(f"Loaded {len(stdin_targets)} target(s) from stdin")

    if not targets and not args.request:
        parser.print_help()
        sys.exit(1)

    normalized_initial_targets = [normalize_url(t) for t in targets]
    final_scan_queue = []
    visited_urls = set()

    # Phase 1: Discovery (only if --discover or --scan-full is used)
    running_discovery = bool(args.discover or (args.scan_full and not args.no_crawl))
    
    if running_discovery:
        from ppmap.discovery import EndpointDiscovery
        discovery_session = requests.Session()
        # Apply stealth if needed
        if args.stealth:
            discovery_session.headers.update(STEALTH_HEADERS)
            
        discovery = EndpointDiscovery(session=discovery_session)
        
        for target in normalized_initial_targets:
            if target in visited_urls:
                continue
            
            print(f"{Colors.BLUE}[*] Discovering endpoints for: {target} (depth={args.max_depth or 1}){Colors.ENDC}")
            try:
                discovered = discovery.discover_endpoints(
                    target, 
                    depth=args.max_depth or 1, 
                    max_endpoints=args.max_endpoints or 30
                )
                for d_url in [target] + discovered:
                    d_url_normalized = normalize_url(d_url)
                    if d_url_normalized not in visited_urls:
                        final_scan_queue.append(d_url_normalized)
                        visited_urls.add(d_url_normalized)
                        if len(final_scan_queue) >= (args.max_urls or 100):
                            break
            except Exception as e:
                logger.error(f"Discovery error for {target}: {e}")
                final_scan_queue.append(target)
                visited_urls.add(target)
            
            if len(final_scan_queue) >= (args.max_urls or 100):
                print(f"{Colors.WARNING}[!] Max URLs ({args.max_urls}) reached during discovery.{Colors.ENDC}")
                break
    else:
        # Just use the initial targets directly if no discovery is requested
        for target in normalized_initial_targets:
            if target not in visited_urls:
                final_scan_queue.append(target)
                visited_urls.add(target)

    # If --discover only, we print and exit
    if args.discover and not (args.scan or args.scan_full):
        print(f"\n{Colors.GREEN}[✓] Discovery complete! Found {len(final_scan_queue)} endpoints:{Colors.ENDC}")
        for url in final_scan_queue:
            print(f"  -> {url}")
        sys.exit(0)

    # --- SCANNING PHASE ---
    if final_scan_queue:
        logger.info(f"Starting Scan phase on {len(final_scan_queue)} unique URL(s)")

        # Use async engine if enabled
        if args.async_scan:
            logger.info(
                f"Using async scanning engine with {args.async_workers} concurrent workers"
            )
            async_scanner = AsyncScanner(
                max_concurrent=args.async_workers, timeout=args.timeout or 30
            )
            results = async_scanner.run_async_scan(final_scan_queue)

            logger.info(f"Async scan completed: {len(results)} results")

            # Generate enhanced reports (always save, even with 0 findings)
            findings = [r for r in results if r.get("success")] if results else []
            report_gen = EnhancedReportGenerator(args.output)
            generated_reports = report_gen.generate_all_formats(
                findings=findings,
                target=", ".join(normalized_initial_targets[:3]) + ("..." if len(normalized_initial_targets) > 3 else ""),
                formats=PPMAP_CONFIG["reporting"]["format"],
            )

            logger.info(f"Generated {len(generated_reports)} report format(s):")
            for fmt, filepath in generated_reports.items():
                logger.info(f"  - {fmt}: {filepath}")
                print(
                    f"{Colors.GREEN}[✓] {fmt.upper()} report: {filepath}{Colors.ENDC}"
                )
        else:
            # Use traditional scanner
            target_iterator = final_scan_queue
            if tqdm is not None:
                target_iterator = tqdm(
                    final_scan_queue, desc="Scanning targets", unit="target"
                )

            from ppmap.service.scan_service import run_scan
            from ppmap.models.config import ScanConfig
            
            scan_config = ScanConfig(
                timeout=PPMAP_CONFIG["scanning"]["timeout"],
                max_workers=PPMAP_CONFIG["scanning"]["max_workers"],
                stealth=PPMAP_CONFIG["scanning"].get("stealth_mode", False),
                verify_ssl=not PPMAP_CONFIG["scanning"].get("disable_ssl_verify", False),
                rate_limit=PPMAP_CONFIG["rate_limiting"].get("requests_per_minute", 60) if PPMAP_CONFIG["rate_limiting"].get("enabled") else None,
                delay=args.delay,
                custom_headers=auth_headers
            )

            all_findings = []
            try:
                for target in target_iterator:
                    try:
                        logger.info(f"Scanning target: {target}")
                        print(f"{Colors.BLUE}[→] Scanning Endpoint: {target}{Colors.ENDC}")
                        
                        # NO MORE DISCOVERY INSIDE THE SCAN LOOP
                        # We already did it in Phase 1
                        scan_session = run_scan(
                            target_url=target,
                            config=scan_config,
                            run_discovery=False
                        )
                        findings = scan_session.findings
                        
                        if findings:
                            all_findings.extend(findings)
                    except Exception as e:
                        logger.error(f"Error scanning {target}: {e}", exc_info=True)
                        continue
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Scan interrupted by user. Generating partial report...{Colors.ENDC}")
                logger.info("Scan interrupted by user. Generating partial report.")

            # Generate reports for traditional scan (always save, even with 0 findings)
            report_gen = EnhancedReportGenerator(args.output)
            generated_reports = report_gen.generate_all_formats(
                findings=all_findings,
                target=", ".join(normalized_initial_targets[:3]) + ("..." if len(normalized_initial_targets) > 3 else ""),
                formats=PPMAP_CONFIG["reporting"]["format"],
            )

            logger.info(f"Generated {len(generated_reports)} report format(s):")
            for fmt, filepath in generated_reports.items():
                logger.info(f"  - {fmt}: {filepath}")
                print(
                    f"{Colors.GREEN}[✓] {fmt.upper()} report: {filepath}{Colors.ENDC}"
                )
    else:
        # This part handles if final_scan_queue is empty but we have a request file
        if args.request:
            # The parse_burp_request logic is already handled above in the script
            pass
        else:
            parser.print_help()

    logger.info("PPMAP completed")


if __name__ == "__main__":
    main()
