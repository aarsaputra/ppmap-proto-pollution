#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.1.0 Enterprise (Scanner | Browser | 0-Day | OOB)

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
from ppmap.scanner.core import CompleteSecurityScanner, safe_execute, progress_iter, Colors

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
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    urllib3_logger = logging.getLogger('urllib3.connectionpool')
    urllib3_logger.setLevel(logging.ERROR)
except ImportError:
    pass

# ============================================================================

# ============================================================================
# PRINT BANNER & DISCLAIMER
# ============================================================================
def print_banner():
    banner = Colors.BOLD + Colors.CYAN + r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.1.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""" + Colors.ENDC + f"""

{Colors.WARNING}⚠️  DISCLAIMER:{Colors.ENDC}
This tool is for AUTHORIZED SECURITY TESTING ONLY.
Unauthorized access to systems is ILLEGAL.
Author assumes NO liability for misuse or damages.
Use only with explicit permission on target systems.

{Colors.GREEN}Run with -h for help, --poc for quick PoC, --scan for full scan{Colors.ENDC}
"""
    print(banner)

# ============================================================================
# DEPENDENCIES CHECK
# ============================================================================
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException, NoSuchElementException,
        StaleElementReferenceException, InvalidSessionIdException
    )
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print(f"{Colors.WARNING}[!] Selenium not available. Install: pip install selenium{Colors.ENDC}")
    logger.error("Selenium not installed")

try:
    import requests
    from bs4 import BeautifulSoup
    import urllib.parse as urlparse
    
    # Suppress SSL warnings for unverified HTTPS (pentest context)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
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
        'scanning': {'timeout': 15, 'max_workers': 3},
        'reporting': {'format': ['json', 'html'], 'output_dir': './reports'}
    }


def main():
    # Setup logging first
    log_level = logging.DEBUG if os.getenv('PPMAP_DEBUG') else logging.INFO
    setup_logging(log_level)
    
    print_banner()
    logger.info("PPMAP started")
    
    parser = argparse.ArgumentParser(
        description="PPMAP v4.1.0 - Prototype Pollution Assessment Platform (Enterprise Edition)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
SCANNING MODES:
  Quick PoC:
    python ppmap.py --poc http://target.com
  
  Full Scan:
    python ppmap.py --scan http://target.com
  
  Multiple targets:
    python ppmap.py --scan http://target1.com http://target2.com http://target3.com
  
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
        """
    )
    
    # Core arguments
    parser.add_argument("--poc", type=str, metavar="URL", help="Run Quick PoC mode on target")
    parser.add_argument("--quickpoc-local", type=str, metavar="URL", help="Run local QuickPoC (uses Playwright/Selenium fallback)")
    parser.add_argument("--scan", nargs='*', metavar="URL", help="Run Full Scan mode on target(s)")
    parser.add_argument("-ls", "--list", type=str, metavar="FILE", help="Read target URLs from file (one URL per line)")
    parser.add_argument("--stdin", action="store_true", help="Read target URLs from stdin (for pipeline: subfinder | httpx | ppmap --scan --stdin)")
    parser.add_argument("--request", "-r", type=str, metavar="FILE", help="Scan from Burp Suite request file (authenticated scan)")
    
    # Configuration
    parser.add_argument("--config", type=str, default="config.yaml", help="Config file (default: config.yaml)")
    
    # Browser options
    parser.add_argument("--browser", type=str, default="chrome", choices=['chrome', 'firefox'], help="Browser to use (chrome|firefox)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout per request in seconds (default: 30)")
    parser.add_argument("--workers", type=int, default=3, help="Max concurrent workers (default: 3)")
    parser.add_argument("--headless", action="store_true", default=True, help="Headless browser (default: True)")
    parser.add_argument("--no-headless", dest="headless", action="store_false", help="Show browser window")
    
    # Stealth & Rate Limiting
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (anti-detection)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--rate-limit", type=int, metavar="N", help="Requests per minute limit")
    parser.add_argument("--user-agent", type=str, help="Custom User-Agent")
    
    # Feature toggles
    parser.add_argument("--disable-jquery-pp", action="store_true", help="Disable jQuery PP tests")
    parser.add_argument("--disable-xss", action="store_true", help="Disable XSS tests")
    parser.add_argument("--disable-waf-bypass", action="store_true", help="Disable WAF bypass tests")
    parser.add_argument("--disable-discovery", action="store_true", help="Disable endpoint discovery")
    
    # Reporting
    parser.add_argument("--output", type=str, default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--format", type=str, default="json,html,csv,xml,md", help="Report formats (json,html,markdown,jupyter,csv,xml,md,pdf)")
    parser.add_argument("--template", type=str, default="modern", help="Report template (modern, minimal, detailed)")
    parser.add_argument("--no-poc", action="store_true", help="Don't include PoC in reports")
    parser.add_argument("--async-scan", action="store_true", help="Enable async scanning engine (EXPERIMENTAL)")
    parser.add_argument("--async-workers", type=int, default=10, help="Max async concurrent workers (default: 10)")
    parser.add_argument("--oob", action="store_true", help="Enable OOB/Blind detection (Uses Interact.sh)")
    
    # Additional options
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (insecure)")
    parser.add_argument("--proxy", type=str, metavar="PROXY", help="HTTP proxy (http://proxy:port)")
    parser.add_argument("--diff", nargs=2, metavar=("FILE1", "FILE2"), help="Compare two scan result files")
    parser.add_argument("--preset", choices=['quick', 'thorough', 'stealth'], help="Use configuration preset (overrides defaults)")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Verbose output (-v, -vv, -vvv)")
    parser.add_argument("--version", action="version", version="PPMAP v4.1.0")
    
    # Argument completion
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
        
    args = parser.parse_args()
    
    # Apply presets if specified
    if args.preset:
        if args.preset == 'quick':
            print(f"{Colors.BLUE}[*] Applying 'QUICK' preset{Colors.ENDC}")
            args.workers = 1
            args.headless = True
            args.disable_waf_bypass = True
            args.oob = False
        elif args.preset == 'thorough':
            print(f"{Colors.BLUE}[*] Applying 'THOROUGH' preset{Colors.ENDC}")
            args.workers = 10
            args.oob = True
            args.verify_ssl = False
        elif args.preset == 'stealth':
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
        PPMAP_CONFIG['scanning']['timeout'] = args.timeout
    if args.workers:
        PPMAP_CONFIG['scanning']['max_workers'] = args.workers
    if args.stealth:
        PPMAP_CONFIG['scanning']['stealth_mode'] = True
    if args.verify_ssl:
        PPMAP_CONFIG['scanning']['disable_ssl_verify'] = False
    if args.insecure:
        PPMAP_CONFIG['scanning']['disable_ssl_verify'] = True
    if args.rate_limit:
        PPMAP_CONFIG['rate_limiting']['enabled'] = True
        PPMAP_CONFIG['rate_limiting']['requests_per_minute'] = args.rate_limit
    
    # Feature toggles
    if args.disable_jquery_pp:
        PPMAP_CONFIG['testing']['jquery_pp'] = False
    if args.disable_xss:
        PPMAP_CONFIG['testing']['xss'] = False
    if args.disable_waf_bypass:
        PPMAP_CONFIG['testing']['waf_bypass'] = False
    
    # Reporting
    if args.format:
        # Split by comma if multiple formats
        PPMAP_CONFIG['reporting']['format'] = args.format.split(',')
    if args.output:
        PPMAP_CONFIG['reporting']['output_dir'] = args.output
    if args.disable_discovery:
        PPMAP_CONFIG['testing']['endpoint_discovery'] = False
    
    # Reporting config handled above
    # PPMAP_CONFIG['reporting']['template'] = args.template
    if args.template:
        PPMAP_CONFIG['reporting']['template'] = args.template
    PPMAP_CONFIG['reporting']['include_poc'] = not args.no_poc
    
    # Async config
    PPMAP_CONFIG['async'] = {
        'enabled': args.async_scan,
        'max_concurrent': args.async_workers,
        'timeout': args.timeout or 30
    }
    
    # Logging verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logger.setLevel(logging.INFO)
    
    logger.debug(f"Configuration: {PPMAP_CONFIG}")
    
    # Handle scan from request file
    if args.request:
        if not parse_burp_request:
            logger.error("Burp parser module not found")
            return
            
        try:
            print(f"{Colors.BLUE}[*] Parsing request file: {args.request}{Colors.ENDC}")
            req_data = parse_burp_request(args.request)
            target_url = req_data['url']
            
            print(f"{Colors.BLUE}[*] Target URL: {target_url}{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Method: {req_data['method']}{Colors.ENDC}")
            
            # Initialize scanner
            ppmap = CompleteSecurityScanner(
                timeout=args.timeout,
                max_workers=args.workers,
                verify_ssl=True,
                oob_enabled=args.oob,
                stealth=PPMAP_CONFIG['scanning'].get('stealth_mode', False)
            )
            
            # Setup authenticated session
            if req_data.get('headers'):
                ppmap.session.headers.update(req_data['headers'])
                # Also update separate scanner session if exists
                if hasattr(ppmap, 'scanner') and hasattr(ppmap.scanner, 'session'):
                    ppmap.scanner.session.headers.update(req_data['headers'])
                    
                print(f"{Colors.GREEN}[✓] Loaded {len(req_data['headers'])} headers (cookies included){Colors.ENDC}")
            
            # Special handling for POST requests (often SSPP)
            if req_data['method'] == 'POST' and req_data.get('body'):
                print(f"{Colors.BLUE}[*] Detected POST body - Prioritizing Server-Side PP checks{Colors.ENDC}")
                
            # Continue with full scan on the URL, passing request data
            ppmap.scan_target(target_url, request_data=req_data)
            
        except Exception as e:
            logger.error(f"Error processing request file: {e}")
            traceback.print_exc()
        return

    if args.poc or getattr(args, 'quickpoc_local', None):
        target_poc_raw = args.poc or args.quickpoc_local
        target_poc = normalize_url(target_poc_raw)
        logger.info(f"Starting Quick PoC mode on {target_poc}")
        run_quick_poc(target_poc, headless=args.headless)
    elif args.scan or args.list or args.stdin:
        # Load targets from -ls file if provided
        targets = list(args.scan) if args.scan else []
        
        if args.list:
            try:
                with open(args.list, 'r') as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    targets.extend(file_targets)
                    logger.info(f"Loaded {len(file_targets)} target(s) from {args.list}")
            except FileNotFoundError:
                print(f"{Colors.FAIL}[!] Error: File '{args.list}' not found{Colors.ENDC}")
                sys.exit(1)
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
                sys.exit(1)
        
        # Read from stdin if --stdin flag is set
        if args.stdin:
            # If stdin is not a terminal, it means data is piped in
            if not sys.stdin.isatty():
                stdin_targets = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]
                targets.extend(stdin_targets)
                logger.info(f"Loaded {len(stdin_targets)} target(s) from stdin")
            else:
                print(f"{Colors.WARNING}[!] No pipe detected. Enter URLs (one per line, Ctrl+D to finish):{Colors.ENDC}")
                stdin_targets = [line.strip() for line in sys.stdin if line.strip() and not line.startswith('#')]
                targets.extend(stdin_targets)
                if stdin_targets:
                    logger.info(f"Loaded {len(stdin_targets)} target(s) from stdin")
        
        if not targets:
            print(f"{Colors.FAIL}[!] No targets to scan{Colors.ENDC}")
            sys.exit(1)
            
        logger.info(f"Starting Full Scan mode on {len(targets)} target(s)")
        
        normalized_targets = [normalize_url(t) for t in targets]

        # Use async engine if enabled
        if args.async_scan:
            logger.info(f"Using async scanning engine with {args.async_workers} concurrent workers")
            async_scanner = AsyncScanner(max_concurrent=args.async_workers, 
                                        timeout=args.timeout or 30)
            results = async_scanner.run_async_scan(normalized_targets)
            
            logger.info(f"Async scan completed: {len(results)} results")
            
            # Generate enhanced reports (always save, even with 0 findings)
            findings = [r for r in results if r.get('success')] if results else []
            report_gen = EnhancedReportGenerator(args.output)
            generated_reports = report_gen.generate_all_formats(
                findings=findings,
                target=", ".join(normalized_targets),
                formats=PPMAP_CONFIG['reporting']['format']
            )
            
            logger.info(f"Generated {len(generated_reports)} report format(s):")
            for fmt, filepath in generated_reports.items():
                logger.info(f"  - {fmt}: {filepath}")
                print(f"{Colors.GREEN}[✓] {fmt.upper()} report: {filepath}{Colors.ENDC}")
        else:
            # Use traditional scanner
            target_iterator = normalized_targets
            if tqdm is not None:
                target_iterator = tqdm(normalized_targets, desc="Scanning targets", unit="target")
            
            scanner = CompleteSecurityScanner(
                timeout=PPMAP_CONFIG['scanning']['timeout'],
                max_workers=PPMAP_CONFIG['scanning']['max_workers'],
                verify_ssl=not PPMAP_CONFIG['scanning'].get('disable_ssl_verify', False),
                oob_enabled=args.oob,
                stealth=PPMAP_CONFIG['scanning'].get('stealth_mode', False)
            )
            
            all_findings = []
            for target in target_iterator:
                try:
                    logger.info(f"Scanning target: {target}")
                    findings = scanner.scan_target(target)
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}", exc_info=True)
                    continue

            # Generate reports for traditional scan (always save, even with 0 findings)
            report_gen = EnhancedReportGenerator(args.output)
            generated_reports = report_gen.generate_all_formats(
                findings=all_findings,
                target=", ".join(normalized_targets),
                formats=PPMAP_CONFIG['reporting']['format']
            )
            
            logger.info(f"Generated {len(generated_reports)} report format(s):")
            for fmt, filepath in generated_reports.items():
                logger.info(f"  - {fmt}: {filepath}")
                print(f"{Colors.GREEN}[✓] {fmt.upper()} report: {filepath}{Colors.ENDC}")
    else:
        parser.print_help()
    
    logger.info("PPMAP completed")

if __name__ == "__main__":
    main()
    