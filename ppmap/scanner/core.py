import time
import json
import urllib.parse
import re
import logging
import random
import traceback
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

# Local imports
from ppmap.utils import Colors, normalize_url, print_section
from ppmap.utils.rate_limit import rate_limited
from ppmap.utils.retry import retry_request
from ppmap.models.findings import Finding, VulnerabilityType, Severity
from ppmap.models.reports import ScanMetrics, ScanReport
from ppmap.config.settings import CONFIG, STEALTH_HEADERS
from ppmap.discovery import EndpointDiscovery, ParameterDiscovery
from ppmap.scanner.payloads import (
    generate_pp_permutations,
    generate_json_permutations,
    SSPP_RCE_GADGETS,
    CLIENT_XSS_GADGETS,
    FRAMEWORK_DOS_PAYLOADS,
    WAF_BYPASS_MUTATIONS,
)

# External optional imports handled safely
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
        UnexpectedAlertPresentException,
    )

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import requests
    from bs4 import BeautifulSoup

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from ppmap.payloads.gadgets import GADGET_PROPERTIES

# Import sub-modules
try:
    from ppmap.browser import get_browser
except Exception:
    get_browser = None

try:
    from ppmap.graphql import scan_graphql
    from ppmap.websocket import scan_websocket
    from ppmap.sast import scan_js
except ImportError:
    scan_graphql = lambda *a, **k: []
    scan_websocket = lambda *a, **k: []
    scan_js = lambda *a, **k: []


# Framework fingerprinting
try:
    from ppmap.utils.fingerprint import (
        detect_frameworks,
        fingerprint_summary,
        get_priority_payloads,
    )
except ImportError:
    detect_frameworks = None

# Burp Suite Parser
try:
    from ppmap.utils.burp_parser import (
        parse_burp_request,
        inject_pp_payload,
        compare_responses,
        get_sspp_payloads,
    )
except ImportError:
    parse_burp_request = None

logger = logging.getLogger(__name__)


def progress_iter(iterable, desc="Processing", disable=False):
    if tqdm is not None and not disable:
        return tqdm(
            iterable,
            desc=desc,
            ncols=80,
            leave=False,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        )
    return iterable


def safe_execute(func, *args, fallback=None, timeout=None, **kwargs):
    try:
        if timeout:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                return future.result(timeout=timeout)
        else:
            return func(*args, **kwargs)
    except TimeoutError:
        logger.warning(f"Timeout executing {func.__name__}")
        return fallback
    except ConnectionError as e:
        logger.error(f"Connection error in {func.__name__}: {str(e)[:100]}")
        return fallback
    except Exception as e:
        logger.error(f"Error in {func.__name__}: {type(e).__name__}: {str(e)[:100]}")
        logger.debug(traceback.format_exc())
        return fallback


from ppmap.payloads import XSS_PAYLOADS, DEFAULT_XSS_PARAMS
from ppmap.models.config import ScanConfig


def extract_jquery_versions_robust(page_source: str, driver=None) -> Dict[str, Any]:
    """
    Enhanced jQuery version detection with priority ordering.
    
    Detection methods (ordered by reliability):
    1. Dynamic: JavaScript execution (jQuery.fn.jquery) - Most accurate if page loads
    2. Script src attributes: <script src="jquery-X.Y.Z.js"> - Explicit version
    3. HTML patterns: Comments, inline scripts - Fallback
    
    Returns:
        {
            'dynamic': '3.3.1',  # From jQuery.fn.jquery execution
            'src_versions': [('1.11.3', 'https://...'), ...],  # From script src
            'pattern_versions': ['1.12.4'],  # From regex patterns
            'recommended': '1.11.3'  # Best guess for actual loaded version
        }
    """
    result = {
        'dynamic': None,
        'src_versions': [],
        'pattern_versions': [],
        'recommended': None,
        'all_versions': set(),
        'detection_method': None
    }
    
    # METHOD 1: Dynamic execution (most accurate)
    if driver:
        try:
            dynamic_version = driver.execute_script(
                "return (typeof jQuery !== 'undefined' ? jQuery.fn.jquery : "
                "(typeof window.jQuery !== 'undefined' ? window.jQuery.fn.jquery : "
                "(typeof $ !== 'undefined' && $.fn ? $.fn.jquery : null)));"
            )
            if dynamic_version:
                result['dynamic'] = dynamic_version
                result['all_versions'].add(dynamic_version)
                logger.debug(f"Dynamic jQuery version: {dynamic_version}")
        except Exception as e:
            logger.debug(f"Dynamic detection failed: {type(e).__name__}")
    
    # METHOD 2: Extract from script src attributes (most explicit)
    try:
        # Extract script tags with src attributes
        script_pattern = r'<script[^>]+src=["\']([^"\']*jquery[^"\']*)["\']'
        for match in re.finditer(script_pattern, page_source, re.IGNORECASE):
            src_url = match.group(1)
            # Extract version from URL: jquery-1.11.3.js, jquery.1-11-3.min.js, etc
            version_match = re.search(r'jquery[.-/]+([\d.]+)', src_url, re.IGNORECASE)
            if version_match:
                version = version_match.group(1).rstrip('.')  # Remove trailing dots
                # Validate version format (at least X.Y)
                if re.match(r'^\d+\.\d+', version):
                    result['src_versions'].append((version, src_url))
                    result['all_versions'].add(version)
                    logger.debug(f"Script src jQuery version: {version} from {src_url[:50]}")
    except Exception as e:
        logger.debug(f"Script src extraction failed: {e}")
    
    # METHOD 3: Regex patterns on page source
    try:
        patterns = [
            r'jquery[/-]([\d.]+)\.js',  # jquery-1.11.3.js or jquery/2.1.1.js
            r'jquery[.-]([\d.]+)',       # jquery-1.11.3 or jquery.2.1.1
            r'jQuery v([\d.]+)',         # jQuery v1.11.3
            r'jquery:\s*["\']?([\d.]+)["\']?',  # jquery: "1.11.3"
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, page_source, re.IGNORECASE):
                version = match.group(1).rstrip('.')  # Remove trailing dots/dots
                # Validate version format (at least X.Y)
                if re.match(r'^\d+\.\d+', version):
                    result['pattern_versions'].append(version)
                    result['all_versions'].add(version)
                    logger.debug(f"Pattern match jQuery version: {version}")
    except Exception as e:
        logger.debug(f"Pattern extraction failed: {e}")
    
    # PRIORITY SELECTION
    # 1. If dynamic script execution worked, that's the actual loaded version
    if result['dynamic']:
        result['recommended'] = result['dynamic']
        result['detection_method'] = 'dynamic_execution'
    # 2. Prefer script src versions (explicit declarations) over patterns
    elif result['src_versions']:
        # Pick the one that appears first in HTML (likely the primary jQuery)
        result['recommended'] = result['src_versions'][0][0]
        result['detection_method'] = 'script_src'
    # 3. Use regex pattern matches (least reliable)
    elif result['pattern_versions']:
        # De-duplicate and sort, preferring older versions (more vulnerable)
        unique_patterns = sorted(list(set(result['pattern_versions'])))
        result['recommended'] = unique_patterns[0]
        result['detection_method'] = 'pattern_fallback'
    
    return result


class CompleteSecurityScanner:
    """Complete jQuery Prototype Pollution & XSS Scanner"""

    def __init__(self, config: Optional[ScanConfig] = None, **kwargs):
        # Fallback for backward compatibility inside tests or implicit calls
        if not config:
            self.config = ScanConfig(
                timeout=kwargs.get("timeout", 15),
                max_workers=kwargs.get("max_workers", 3),
                verify_ssl=kwargs.get("verify_ssl", True),
                oob_enabled=kwargs.get("oob_enabled", False),
                stealth=kwargs.get("stealth", False),
            )
        else:
            self.config = config

        self.timeout = self.config.timeout
        self.max_workers = self.config.max_workers
        self.stealth = self.config.stealth
        self.oob_enabled = self.config.oob_enabled
        self.oob_detector = None

        if self.oob_enabled:
            pass  # We will lazy init in test_blind_oob or main scan to avoid startup delay

        # Initialize session with proper headers to avoid WAF fingerprinting
        self.session = requests.Session()
        self.session.verify = self.config.verify_ssl

        if self.stealth:
            # Apply realistic browser headers so WAF sees a real browser
            self.session.headers.update(STEALTH_HEADERS)
            logger.info(
                "Stealth mode: applied realistic browser headers to HTTP session"
            )
        else:
            # Even without stealth, set a basic User-Agent to avoid python-requests fingerprint
            self.session.headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                }
            )

        self.driver = None
        self.findings = []
        self.prototype_snapshot = None
        self.param_discovery = ParameterDiscovery(self.session)
        self.metrics = ScanMetrics(start_time=time.time())

    def snapshot_object_prototype(self):
        """Capture Object.prototype state"""
        try:
            snapshot_script = """
            return Object.getOwnPropertyNames(Object.prototype).reduce((acc, prop) => {
                try { acc[prop] = Object.prototype[prop]; } catch(e) {}
                return acc;
            }, {});
            """
            return self.driver.execute_script(snapshot_script)
        except Exception as e:
            logger.debug(f"Returning None due to error: {type(e).__name__} - {e}")
            return None

    def restore_object_prototype(self, snapshot):
        """Restore Object.prototype from snapshot"""
        if not snapshot:
            return
        try:
            restore_script = "Object.getOwnPropertyNames(Object.prototype).forEach(prop => { if (!window.__ppmap_protected) { delete Object.prototype[prop]; } });"
            self.driver.execute_script(restore_script)
        except Exception as e:
            logger.debug(f"Ignored error: {type(e).__name__} - {e}")

    def verify_cleanup(self, props_to_check=None):
        """Verify prototype cleanup"""
        try:
            verify_script = """
            const checked = arguments[0] || [];
            const polluted = checked.filter(prop => Object.prototype[prop] !== undefined);
            return { 'prototype_ok': polluted.length === 0, 'details': { 'prototype': polluted } };
            """
            return self.driver.execute_script(verify_script, props_to_check or [])
        except Exception as e:
            logger.debug(
                f"Returning {'prototype_ok': True} due to error: {type(e).__name__} - {e}"
            )
            return {"prototype_ok": True}

    def verify_prototype_pollution(self, prop_name: str) -> bool:
        """Execute JS to verify if Object.prototype was actually polluted.

        This is the universal check used across all PP tests to eliminate
        false positives. Returns True only if the property exists on
        Object.prototype (meaning real pollution occurred).
        """
        if not self.driver:
            return False
        try:
            result = self.driver.execute_script(
                f"return Object.prototype.hasOwnProperty('{prop_name}');"
            )
            return result is True
        except Exception as e:
            logger.debug(f"PP verification error for '{prop_name}': {type(e).__name__} - {e}")
            return False

    def verify_sspp(self, target_url: str) -> dict:
        """Verify Server-Side Prototype Pollution via canary injection.

        Injects a unique canary key into __proto__ via JSON POST, then
        checks if the canary persists in a subsequent clean GET response.
        Returns dict with 'polluted' bool and 'canary' string.
        """
        canary = f"ppmap_{int(time.time() * 1000)}"
        result = {"polluted": False, "canary": canary}
        try:
            # Step 1: Inject canary via __proto__
            payload = {"__proto__": {canary: "ppmap_verified"}}
            self.session.post(
                target_url,
                json=payload,
                timeout=self.timeout,
                verify=False,
            )
            # Step 2: Make a clean GET and check if canary leaked
            clean_resp = self.session.get(
                target_url, timeout=self.timeout, verify=False
            )
            if canary in clean_resp.text or "ppmap_verified" in clean_resp.text:
                result["polluted"] = True
            # Step 3: Also check if response has unexpected new keys
            try:
                resp_json = clean_resp.json()
                if isinstance(resp_json, dict) and canary in str(resp_json):
                    result["polluted"] = True
            except (ValueError, TypeError):
                pass
        except Exception as e:
            logger.debug(f"SSPP verification error: {type(e).__name__} - {e}")
        return result

    def get_pp_confidence(self, alerts_detected: bool, is_polluted: bool,
                          has_sinks: bool, has_console_errors: bool) -> float:
        """Calculate confidence score (0.0–1.0) for a PP finding.

        - 1.0: JS alert() executed successfully
        - 0.9: Object.prototype[key] verified as polluted via JS
        - 0.7: SSPP canary detected in response
        - 0.5: Browser console error related to PP
        - 0.3: Sink detected but no pollution confirmed
        """
        if alerts_detected:
            return 1.0
        if is_polluted:
            return 0.9
        if has_console_errors:
            return 0.5
        if has_sinks:
            return 0.3
        return 0.0

    def check_target_status(self, target_url: str) -> bool:
        """Verify the target implies standard HTTP accessibility."""
        try:
            resp = self.session.get(target_url, verify=self.session.verify, timeout=self.timeout)
            if resp.status_code >= 400 and resp.status_code not in (401, 403, 404):
                logger.warning(f"Target returned status code {resp.status_code}")
                # We still return True because security testing can occur on error pages
                return True
            return True
        except Exception as e:
            logger.error(f"Cannot connect to target: {e}")
            return False

    def setup_browser(self, target_url: str) -> bool:
        """Initialize browser driver context for scanner."""
        if not get_browser:
            logger.debug("get_browser module not loaded")
            return False
            
        try:
            self.driver = get_browser(headless=True)
            self.driver.set_page_load_timeout(self.timeout)
            self.driver.get(target_url)
            # Add a short delay to allow JS frameworks to initialize
            time.sleep(2)
            logger.info("Browser initialized and navigated to target successfully")
            return True
        except Exception as e:
            logger.error(f"Browser setup failed: {e}")
            return False

    def scan_target(self, target_url, request_data=None, run_discovery=True):
        """Scan single target orchestrator"""
        all_findings = []

        # Strict Liveness Check
        if not self.check_target_status(target_url):
            return []

        print_section(f"FULL SCAN MODE - Target: {target_url}")

        if not self.setup_browser(target_url):
            return []

        # Reset and start metrics
        self.metrics = ScanMetrics(start_time=time.time())

        # Fingerprint Frameworks
        if detect_frameworks is not None:
            print(f"{Colors.BLUE}[*] Detecting frameworks and technologies...{Colors.ENDC}")
            try:
                resp = self.session.get(target_url, verify=self.session.verify, timeout=self.timeout)
                self.metrics.total_requests += 1

                detected = detect_frameworks(resp.text, resp.headers)
                summary = fingerprint_summary(detected)
                print(summary)
            except Exception as e:
                print(f"{Colors.WARNING}[!] Fingerprinting failed: {e}{Colors.ENDC}")

        try:
            from ppmap.scanner.tier0_basic import Tier0BasicScanner
            from ppmap.scanner.tier1_blind import Tier1BlindScanner
            from ppmap.scanner.tier2_framework import Tier2FrameworkScanner
            from ppmap.scanner.tier3_portswigger import Tier3PortSwiggerScanner
            from ppmap.scanner.tier4_evasion import Tier4EvasionScanner
            from ppmap.scanner.tier5_research import Tier5ResearchScanner
            from ppmap.scanner.tier6_cve import Tier6CVEScanner
            from ppmap.scanner.tier7_advanced import Tier7AdvancedScanner
            from ppmap.scanner.base import ScanContext

            ctx = ScanContext(
                driver=self.driver,
                session=self.session,
                config=self.config,
                target_url=target_url,
                request_data=request_data
            )
            ctx.legacy_metrics = self.metrics

            tiers = [
                Tier0BasicScanner(),
                Tier1BlindScanner(),
                Tier2FrameworkScanner(),
                Tier3PortSwiggerScanner(),
                Tier4EvasionScanner(),
                Tier5ResearchScanner(),
                Tier6CVEScanner(),
                Tier7AdvancedScanner()
            ]

            all_findings = []
            for tier in tiers:
                try:
                    findings = tier.run(ctx)
                    all_findings.extend(findings)
                except (TimeoutException, WebDriverException) as e:
                    logger.error(f"[!] {tier.tier_name} triggered a fatal browser error: {e}. Recovering session...")
                    try:
                        self.driver.quit()
                    except Exception:
                        pass
                    # Re-initialize browser and update context
                    if not self.setup_browser(target_url):
                        logger.error("[!] Browser recovery failed. Aborting further tier execution.")
                        break
                    ctx.driver = self.driver
                except Exception as e:
                    logger.error(f"[!] {tier.tier_name} failed: {e}")

            # Backwards compat for report generation requirements
            jquery_findings = []
            xss_findings = []
            dom_xss_pp_findings = []
            
            for f in all_findings:
                title = getattr(f, 'name', '') or str(f)
                if 'jQuery' in title:
                    jquery_findings.append(f)
                elif 'XSS' in title:
                    xss_findings.append(f)
                    if 'DOM' in title:
                        dom_xss_pp_findings.append(f)

            total = len(all_findings)
            self.metrics.end_time = time.time()
            self.metrics.vulnerabilities_found = total

            print(f"\n{Colors.BOLD}{Colors.GREEN}Scan Complete! Vulnerabilities Found: {total}{Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Scan Duration: {self.metrics.duration:.2f}s | Success Rate: {self.metrics.success_rate:.1f}%{Colors.ENDC}")

            if total > 0:
                print(f"{Colors.CYAN}Orchestrated Tier Scanning Complete. Generating detailed report...{Colors.ENDC}")
                self.save_reports(target_url, all_findings, jquery_findings, xss_findings, dom_xss_pp_findings)
            else:
                print(f"{Colors.GREEN}[✓] No vulnerabilities detected.{Colors.ENDC}")
                self.save_reports(target_url, [], [], [], [])

        except Exception as e:
            print(f"{Colors.FAIL}[!] Scan error: {str(e)}{Colors.ENDC}")
        finally:
            if self.driver:
                self.driver.close()

        for f in all_findings:
            if isinstance(f, Finding):
                if not f.url:  f.url = target_url
            elif isinstance(f, dict):
                if "url" not in f: f["url"] = target_url

        return all_findings

    def save_reports(
        self,
        target_url,
        all_findings,
        jquery_findings,
        xss_findings,
        dom_xss_pp_findings=None,
    ):
        """Generate and save HTML/JSON reports in target-specific folder"""
        if dom_xss_pp_findings is None:
            dom_xss_pp_findings = []
        try:
            # Extract domain from URL for folder name
            parsed_url = urllib.parse.urlparse(target_url)
            domain = parsed_url.netloc.replace(".", "_").replace(":", "_")

            # Create target-specific folder: report/domain_timestamp/
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_folder = os.path.join("report", f"{domain}_{timestamp}")

            if not os.path.exists(target_folder):
                os.makedirs(target_folder)

            # Save JSON report
            json_file = os.path.join(target_folder, "report.json")
            json_data = {
                "scan_date": datetime.now().isoformat(),
                "target": target_url,
                "total_vulnerabilities": len(all_findings),
                "jquery_pp_count": len(jquery_findings),
                "xss_count": len(xss_findings),
                "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in all_findings],
            }

            with open(json_file, "w") as f:
                json.dump(json_data, f, indent=2)

            print(f"{Colors.GREEN}[✓] JSON Report saved: {json_file}{Colors.ENDC}")

            # Save HTML report
            dict_findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in all_findings]
            html_file = os.path.join(target_folder, "report.html")
            html_content = self.generate_html_report(
                target_url,
                dict_findings,
                [f.to_dict() if hasattr(f, "to_dict") else f for f in jquery_findings],
                [f.to_dict() if hasattr(f, "to_dict") else f for f in xss_findings],
                [f.to_dict() if hasattr(f, "to_dict") else f for f in dom_xss_pp_findings],
            )
            with open(html_file, "w") as f:
                f.write(html_content)

            print(f"{Colors.GREEN}[✓] HTML Report saved: {html_file}{Colors.ENDC}")
            print(f"{Colors.GREEN}[✓] Reports folder: {target_folder}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Failed to save reports: {str(e)}{Colors.ENDC}")

    def generate_html_report(
        self,
        target_url,
        all_findings,
        jquery_findings,
        xss_findings,
        dom_xss_pp_findings=None,
    ):
        """Delegate to reports layer (clean architecture). See ppmap/reports/html_report.py"""
        from ppmap.reports.html_report import generate_html_report as _gen
        return _gen(target_url, all_findings, jquery_findings, xss_findings, dom_xss_pp_findings)

    def _generate_html_report_legacy(
        self,
        target_url,
        all_findings,
        jquery_findings,
        xss_findings,
        dom_xss_pp_findings=None,
    ):
        """Generate detailed HTML report with all findings including WAF bypasses and endpoints"""
        if dom_xss_pp_findings is None:
            dom_xss_pp_findings = []
        # Categorize findings
        waf_bypasses = [f for f in all_findings if f.get("type") == "waf_bypass"]
        discovered_endpoints = [
            f for f in all_findings if f.get("type") == "discovered_endpoint"
        ]
        blind_pp_findings = [
            f
            for f in all_findings
            if f.get("type")
            in [
                "blind_pp_detected",
                "persistent_pp",
                "status_override_detected",
                "function_prototype_pollution",
                "persistent_prototype_pollution",
            ]
        ]
        react_flight_findings = [
            f for f in all_findings if f.get("type") == "react_flight_vulnerability"
        ]
        sveltekit_findings = [
            f
            for f in all_findings
            if f.get("type")
            in ["sveltekit_superforms_pollution", "sveltekit_url_pollution"]
        ]
        charset_findings = [
            f for f in all_findings if f.get("type") == "charset_override_detected"
        ]

        report_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PPMAP v3.7 - Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%); color: #fff; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 8px 0; font-size: 14px; opacity: 0.9; }}
        .section {{ background: white; margin: 20px 0; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .section h2 {{ margin-top: 0; color: #1a1a1a; border-bottom: 3px solid #f44; padding-bottom: 10px; }}
        .section h3 {{ color: #333; margin-top: 20px; margin-bottom: 15px; }}
        .vulnerability {{ background: #fee; border-left: 5px solid #f44; padding: 15px; margin: 12px 0; border-radius: 4px; }}
        .waf_bypass {{ background: #fff3e0; border-left: 5px solid #ff9800; padding: 15px; margin: 12px 0; border-radius: 4px; }}
        .endpoint {{ background: #e3f2fd; border-left: 5px solid #2196f3; padding: 15px; margin: 12px 0; border-radius: 4px; }}
        .success {{ background: #d4edda; border-left: 5px solid #28a745; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .stats {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .stat {{ background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); padding: 18px; border-radius: 8px; flex: 1; min-width: 150px; text-align: center; border: 1px solid #dee2e6; }}
        .stat-label {{ font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-number {{ font-size: 36px; font-weight: bold; color: #f44; margin: 10px 0; }}
        code {{ background: #f5f5f5; padding: 3px 8px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; }}
        .payload-code {{ background: #1a1a1a; color: #00ff00; padding: 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto; border: 1px solid #444; }}
        .table-container {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #333; }}
        tr:hover {{ background: #f9f9f9; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .info {{ color: #1976d2; font-weight: bold; }}
        a {{ color: #1976d2; text-decoration: none; word-break: break-all; }}
        a:hover {{ text-decoration: underline; }}
        .verification {{ background: #f5f5f5; border: 1px solid #ddd; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 12px; margin: 10px 0; }}
        .verification-title {{ font-weight: bold; margin-bottom: 8px; color: #333; }}
        .method-label {{ display: inline-block; background: #e0e0e0; padding: 4px 8px; border-radius: 3px; font-size: 12px; margin-bottom: 8px; color: #333; }}
        ul {{ line-height: 1.8; }}
        footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #999; border-top: 1px solid #ddd; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PPMAP v3.7 - Security Assessment Report</h1>
            <p><strong>Target:</strong> {html_escape(target_url)}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-label">Total Findings</div>
                    <div class="stat-number">{len(all_findings)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">WAF Bypasses</div>
                    <div class="stat-number">{len(waf_bypasses)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Discovered Endpoints</div>
                    <div class="stat-number">{len(discovered_endpoints)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Prototype Pollution</div>
                    <div class="stat-number">{len(jquery_findings)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">XSS</div>
                    <div class="stat-number">{len(xss_findings)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">DOM XSS + PP</div>
                    <div class="stat-number">{len(dom_xss_pp_findings)}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Detailed Findings</h2>
"""

        if len(all_findings) == 0:
            report_html += '<div class="success"><strong>✓ No security issues detected!</strong></div>'
        else:
            # DOM XSS + Prototype Pollution findings (highest priority)
            if dom_xss_pp_findings:
                report_html += f"<h3>🔴 DOM-Based XSS with Prototype Pollution (CRITICAL) ({len(dom_xss_pp_findings)} found)</h3>"
                for idx, finding in enumerate(dom_xss_pp_findings, 1):
                    key = finding.get("key", "Unknown")
                    payload = finding.get("payload", "")
                    severity = finding.get("severity", "CRITICAL")
                    verified = finding.get("verified", False)
                    alert_triggered = finding.get("alert_triggered", False)

                    report_html += f"""
            <div class="vulnerability">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - DOM XSS via Prototype Pollution Property: {html_escape(key)}</strong>
                    <span class="method-label critical">{severity}</span>
                    {' [✓ VERIFIED - Alert Triggered]' if alert_triggered else (' [⚠ Reflected]' if finding.get('reflected') else '')}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Vulnerable Property Key:</strong><br>
                    <div class="payload-code">{html_escape(key)}</div>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Payload:</strong><br>
                    <div class="payload-code">{html_escape(payload)}</div>
                </div>
                <div>
                    <strong>Manual Verification:</strong><br>
                    <div class="verification">
                        <div class="verification-title">Test URL:</div>
                        {html_escape(target_url)}?{html_escape(key)}={html_escape(payload)}<br><br>
                        <div class="verification-title">Using curl:</div>
                        <code>curl "{html_escape(target_url)}?{html_escape(key)}={html_escape(payload)}"</code><br><br>
                        <div class="verification-title">Expected Behavior:</div>
                        If vulnerable, the page will execute JavaScript code. For data: URLs with alert, you should see a JavaScript alert popup. For transport_url and similar properties, check if the payload is processed by the application logic.
                    </div>
                </div>
                <div style="margin-top: 15px;">
                    <strong>Why This Is Critical:</strong><br>
                    <div class="verification">
                        Prototype Pollution combined with DOM-based XSS allows an attacker to:<br>
                        1. Pollute the Object prototype with malicious properties<br>
                        2. Inject XSS payloads through those properties<br>
                        3. Execute arbitrary JavaScript in the victim's browser<br>
                        4. Steal session cookies, perform CSRF attacks, deface the site, etc.
                    </div>
                </div>
            </div>
"""

            # WAF Bypass Techniques - ALWAYS DISPLAY (fixed condition)
            if waf_bypasses:
                report_html += (
                    f"<h3>🛡️ WAF Bypass Techniques ({len(waf_bypasses)} found)</h3>"
                )
                report_html += """
            <div style="background: #fff9e6; border-left: 5px solid #ff9800; padding: 15px; margin: 12px 0; border-radius: 4px;">
                <strong>ℹ️ How to Verify WAF Bypass:</strong>
                <div style="margin-top: 10px; font-size: 13px;">
                    <ol>
                        <li><strong>Test Each Variation:</strong> Copy the payload and paste it in the test URL</li>
                        <li><strong>Check Response Status:</strong> If server accepts it (status 200), WAF may be bypassed</li>
                        <li><strong>Look for Reflected Values:</strong> If payload appears in response, it may have passed the filter</li>
                        <li><strong>Test in Browser Console:</strong> Verify if Prototype Pollution actually occurred</li>
                        <li><strong>Monitor Response Headers:</strong> Check for custom headers that indicate pollution</li>
                    </ol>
                </div>
            </div>
"""
                for idx, finding in enumerate(waf_bypasses, 1):
                    method = finding.get("method", "Unknown")
                    payload = finding.get("payload", "")
                    severity = finding.get("severity", "HIGH")
                    
                    # Pre-calculate escaped strings to avoid backslashes in f-string (Python < 3.12 compatibility)
                    curl_payload = payload.replace('"', '\\"')
                    escaped_payload = html_escape(curl_payload)
                    escaped_target_url = html_escape(target_url)
                    escaped_method = html_escape(method)

                    report_html += f'''
            <div class="waf_bypass">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - WAF Bypass via {escaped_method}</strong>
                    <span class="method-label">{severity}</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Bypass Technique:</strong> {escaped_method}<br>
                    <strong>Description:</strong> This payload attempts to bypass WAF filters using {html_escape(method.lower())} techniques.
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Payload:</strong><br>
                    <div class="payload-code">{html_escape(payload)}</div>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Manual Verification Steps:</strong><br>
                    <div class="verification">
                        <div class="verification-title">1. Test via Browser URL:</div>
                        Open in your browser: <code style="word-break: break-all;">{escaped_target_url}?{html_escape(payload)}</code><br><br>
                        
                        <div class="verification-title">2. Test via curl (Check HTTP Status):</div>
                        <code style="display: block; margin: 10px 0;">curl -v "{escaped_target_url}?{escaped_payload}"</code>
                        Look for: Status 200 = Payload accepted, Status 403/400 = Blocked by WAF<br><br>
                        
                        <div class="verification-title">3. Check if Payload is Reflected:</div>
                        escaped_payload = html_escape(payload.replace('"', '\\\\\"'))
                        <code style="display: block; margin: 10px 0;">curl -s "{escaped_target_url}?{escaped_payload}" | grep -i "__proto__"</code>
                        If you see the payload in response = Potentially vulnerable<br><br>
                        
                        <div class="verification-title">4. Browser Console Verification:</div>
                        <code style="display: block; margin: 10px 0;">let obj = {{}};
console.log(obj.polluted);  // Check if prototype was polluted</code><br><br>
                        
                        <div class="verification-title">Expected Behavior:</div>
                        ✓ HTTP status 200 (not 403/400)<br>
                        ✓ Payload appears in response<br>
                        ✓ Object.prototype shows new properties in console<br>
                        ✓ No WAF error page displayed
                    </div>
                </div>
            </div>
'''

            # Blind Prototype Pollution Detection (NEW v3.1)
            if blind_pp_findings:
                report_html += f"<h3>🔍 Blind Server-Side Prototype Pollution ({len(blind_pp_findings)} found)</h3>"
                report_html += """
            <div style="background: #ffe6e6; border-left: 5px solid #d32f2f; padding: 15px; margin: 12px 0; border-radius: 4px;">
                <strong>⚠️ CRITICAL: Blind Prototype Pollution Detected</strong>
                <div style="margin-top: 10px; font-size: 13px;">
                    <p><strong>What This Means:</strong> The server is vulnerable to prototype pollution that cannot be directly observed. The vulnerability was detected via side-channel techniques:</p>
                    <ul>
                        <li><strong>JSON Spaces Override:</strong> Response formatting changes indicate prototype modification</li>
                        <li><strong>Status Code Override:</strong> HTTP status codes change based on polluted properties</li>
                        <li><strong>Persistence:</strong> Pollution affects <strong>ALL USERS</strong> until server restart (CRITICAL)</li>
                        <li><strong>Function.prototype:</strong> Advanced constructor chains allow RCE gadgets</li>
                    </ul>
                    <p><strong>Risk Level:</strong> <span style="color: #d32f2f; font-weight: bold;">CRITICAL</span> - Can affect entire application and all users</p>
                </div>
            </div>
"""
                for idx, finding in enumerate(blind_pp_findings, 1):
                    method = finding.get("method", "Unknown")
                    severity = finding.get("severity", "HIGH")
                    description = finding.get(
                        "description", "Blind prototype pollution detected"
                    )
                    finding_type = finding.get("type", "unknown")

                    # Determine color based on severity
                    if severity == "CRITICAL" or "PERSISTENT" in description.upper():
                        color = "#d32f2f"
                    else:
                        color = "#f57c00"

                    report_html += f"""
            <div class="vulnerability" style="background: #fee; border-left: 5px solid {color};">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - {html_escape(method)}</strong>
                    <span class="method-label" style="background-color: {color}; color: white;">{severity}</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Type:</strong> {html_escape(finding_type.upper())}<br>
                    <strong>Description:</strong> {html_escape(description)}
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Technical Details:</strong><br>
                    <div class="verification">
"""
                    if finding_type == "blind_pp_detected":
                        report_html += """
                        <strong>Detection Method:</strong> JSON Spaces Overflow<br>
                        <p>The server's JSON response formatting changes when prototype is polluted. This is detected by:</p>
                        <ol>
                            <li>Baseline request: normal response size</li>
                            <li>Pollution request: {"__proto__": {"json spaces": 10}}</li>
                            <li>If response size increases by 30%+, prototype pollution succeeded</li>
                        </ol>
                        <p><strong>Remediation:</strong> Update Node.js/Express, validate all user input, use Object.freeze() for critical prototypes</p>
"""
                    elif finding_type == "status_override_detected":
                        status_code = finding.get("status_code", 418)
                        report_html += f"""
                        <strong>Detection Method:</strong> HTTP Status Code Override<br>
                        <p>The server returned HTTP {status_code} instead of normal error code. This indicates:</p>
                        <ol>
                            <li>Payload: {{"__proto__": {{"status": {status_code}}}}}</li>
                            <li>Server accepted the pollution and used it in response logic</li>
                            <li>Attacker can modify HTTP status codes for all users</li>
                        </ol>
                        <p><strong>Remediation:</strong> Sanitize all user input before merge operations, use lodash >= 4.17.11</p>
"""
                    elif finding_type == "function_prototype_pollution":
                        report_html += """
                        <strong>Detection Method:</strong> Function.prototype Chain Access<br>
                        <p>Advanced bypass detected via constructor.constructor.prototype. This is more dangerous because:</p>
                        <ol>
                            <li>Affects ALL functions in the application (not just objects)</li>
                            <li>Can be used for RCE via Function constructor</li>
                            <li>Bypasses basic __proto__ filters</li>
                        </ol>
                        <p><strong>Example RCE Chain:</strong> constructor.constructor("return process.mainModule.require('child_process').exec('command')")( )</p>
"""
                    elif finding_type == "persistent_prototype_pollution":
                        report_html += """
                        <strong>Detection Method:</strong> Cross-Request Persistence<br>
                        <p><strong style="color: #d32f2f;">CRITICAL:</strong> Pollution persists across requests. This means:</p>
                        <ol>
                            <li>One malicious request pollutes Object.prototype</li>
                            <li>ALL subsequent requests (from all users) are affected</li>
                            <li>Pollution remains until server restart</li>
                            <li>Single request = Global compromise</li>
                        </ol>
                        <p><strong style="color: #d32f2f;">Impact:</strong> Entire server is compromised. Every user becomes an admin.</p>
                        <p><strong>Immediate Action Required:</strong> Restart server, review logs for exploitation attempts</p>
"""

                    report_html += """
                    </div>
                </div>
            </div>
"""

            # Tier 2: React 19/Next.js Flight Protocol
            if react_flight_findings:
                report_html += f"<h3>⚛️ React 19/Next.js Flight Protocol (CRITICAL) ({len(react_flight_findings)} found)</h3>"
                report_html += """
            <div style="background: #ffebee; border-left: 5px solid #c62828; padding: 15px; margin: 12px 0; border-radius: 4px;">
                <strong>🚨 CRITICAL: React Flight Protocol Vulnerability</strong>
                <div style="margin-top: 10px; font-size: 13px;">
                    <p><strong>RESEARCH-2024-REACT-FLIGHT (React) / RESEARCH-2024-NEXTJS-FLIGHT (Next.js):</strong></p>
                    <ul>
                        <li>Deserialization flaw in Flight protocol (RSC payloads)</li>
                        <li>Allows constructor chain traversal without strict PP checks</li>
                        <li><strong>Impact:</strong> Unauthenticated Remote Code Execution (RCE)</li>
                        <li><strong>Affected:</strong> Next.js App Router, React 19 with Server Components</li>
                        <li><strong>Risk:</strong> ANY endpoint can be exploited (no Server Actions needed)</li>
                    </ul>
                </div>
            </div>
"""
                for idx, finding in enumerate(react_flight_findings, 1):
                    method = finding.get("method", "FLIGHT_UNKNOWN")
                    payload = finding.get("payload", "")
                    cve = finding.get("cve", "RESEARCH-2024-REACT-FLIGHT")

                    report_html += f"""
            <div class="vulnerability" style="background: #fee; border-left: 5px solid #c62828;">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - {html_escape(method)}</strong>
                    <span class="method-label" style="background-color: #c62828; color: white;">CRITICAL</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>CVE:</strong> {cve}<br>
                    <strong>Payload Pattern:</strong><br>
                    <div class="payload-code">{html_escape(payload)}</div>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Exploitation Method:</strong><br>
                    <div class="verification">
                        <p><strong>1. Identify React Flight Endpoints:</strong></p>
                        <code>curl -H "X-React-Flight: true" https://target/_next/data</code>
                        <br><br>
                        <p><strong>2. Send Malicious Flight Payload:</strong></p>
                        <code>POST /api/endpoint HTTP/1.1<br>Content-Type: application/json<br><br>{{"_formData": {{"get": "$1:then:constructor:constructor"}}}}</code>
                        <br><br>
                        <p><strong>3. Execute RCE via Function Constructor:</strong></p>
                        <code>constructor("return require('child_process').execSync('whoami')")()</code>
                        <br><br>
                        <p><strong>Immediate Action:</strong> Update React to latest, enable strict deserialization checks</p>
                    </div>
                </div>
            </div>
"""

            # Tier 2: SvelteKit/Superforms
            if sveltekit_findings:
                report_html += f"<h3>🟠 SvelteKit/Superforms Vulnerability ({len(sveltekit_findings)} found)</h3>"
                report_html += """
            <div style="background: #fff3e0; border-left: 5px solid #e65100; padding: 15px; margin: 12px 0; border-radius: 4px;">
                <strong>⚠️ CRITICAL: SvelteKit/Superforms PP</strong>
                <div style="margin-top: 10px; font-size: 13px;">
                    <p><strong>RESEARCH-2024-SVELTEKIT-RCE:</strong> Prototype pollution via __superform_file___proto__ pattern</p>
                    <p><strong>RESEARCH-2024-DEVALUE:</strong> Devalue deserialization flaw</p>
                    <ul>
                        <li>Form processing allows PP via __superform_* keys</li>
                        <li>Can pollute nodemailer settings for RCE</li>
                        <li><strong>Impact:</strong> Remote Code Execution via email functions</li>
                        <li><strong>Attack:</strong> Pollute sendmail path → execute arbitrary commands</li>
                    </ul>
                </div>
            </div>
"""
                for idx, finding in enumerate(sveltekit_findings, 1):
                    method = finding.get("method", "SVELTEKIT_UNKNOWN")
                    payload = finding.get("payload", "")
                    cve = finding.get("cve", "RESEARCH-2024-SVELTEKIT-RCE")

                    report_html += f"""
            <div class="vulnerability" style="background: #fff3e0; border-left: 5px solid #e65100;">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - {html_escape(method)}</strong>
                    <span class="method-label" style="background-color: #e65100; color: white;">CRITICAL</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>CVE:</strong> {cve}<br>
                    <strong>Payload:</strong><br>
                    <div class="payload-code">{html_escape(payload)}</div>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Exploitation:</strong><br>
                    <div class="verification">
                        <p><strong>Form Data Pollution:</strong></p>
                        <code>POST /form HTTP/1.1<br>__superform_files___proto__.path=/bin/bash<br>__superform_files___proto__.args=-c,whoami</code>
                        <br><br>
                        <p><strong>Nodemailer Gadget Chain:</strong></p>
                        <code>Pollution → sendmail path → child_process.spawn → RCE</code>
                        <br><br>
                        <p><strong>Mitigation:</strong> Update SvelteKit, disable superforms if not needed</p>
                    </div>
                </div>
            </div>
"""

            # Tier 2: Charset Override
            if charset_findings:
                report_html += f"<h3>🔤 Charset Override & Encoding Bypass ({len(charset_findings)} found)</h3>"
                report_html += """
            <div style="background: #f3e5f5; border-left: 5px solid #6a1b9a; padding: 15px; margin: 12px 0; border-radius: 4px;">
                <strong>⚠️ HIGH: Charset Override Detected</strong>
                <div style="margin-top: 10px; font-size: 13px;">
                    <ul>
                        <li><strong>UTF-7 Encoding Bypass:</strong> Can bypass WAF filters</li>
                        <li><strong>ISO-2022 Bypass:</strong> Special encoding handling</li>
                        <li><strong>Double Encoding:</strong> Multiple encoding layers</li>
                        <li><strong>Impact:</strong> Bypass WAF/security checks, enable PP attacks</li>
                    </ul>
                </div>
            </div>
"""
                for idx, finding in enumerate(charset_findings, 1):
                    method = finding.get("method", "CHARSET_UNKNOWN")
                    encoding = finding.get("encoding", "unknown")
                    payload = finding.get("payload", "")

                    report_html += f"""
            <div class="vulnerability" style="background: #f3e5f5; border-left: 5px solid #6a1b9a;">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - {html_escape(method)}</strong>
                    <span class="method-label" style="background-color: #6a1b9a; color: white;">HIGH</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Encoding:</strong> {html_escape(encoding)}<br>
                    <strong>Detection Method:</strong> Server accepts {html_escape(encoding)} charset
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Exploitation:</strong><br>
                    <div class="verification">
                        <p><strong>1. Bypass WAF with {html_escape(encoding)}:</strong></p>
                        <code>POST / HTTP/1.1<br>Content-Type: application/json; charset={html_escape(encoding)}<br><br>{{payload}}</code>
                        <br><br>
                        <p><strong>2. UTF-7 Example:</strong></p>
                        <code>+ACo-__proto__+ACo-+AD0-+ACo-admin+ACo-+AD0-true</code>
                        <br><br>
                        <p><strong>Why It Works:</strong> Server parses payload in {html_escape(encoding)}, bypassing literal string filters</p>
                        <p><strong>Mitigation:</strong> Whitelist accepted charsets, filter before decoding</p>
                    </div>
                </div>
            </div>
"""

            # Discovered Endpoints
            if discovered_endpoints:
                report_html += f"<h3>🔗 Discovered Endpoints ({len(discovered_endpoints)} found)</h3>"
                report_html += """
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for endpoint in discovered_endpoints:
                    url = endpoint.get("url", "")
                    status = endpoint.get("status", "N/A")
                    size = endpoint.get("size", "N/A")
                    status_class = "critical" if status >= 400 else "info"

                    report_html += f"""
                        <tr>
                            <td><a href="{html_escape(url)}" target="_blank">{html_escape(url)}</a></td>
                            <td><span class="{status_class}">{status}</span></td>
                            <td>{size} bytes</td>
                        </tr>
"""
                report_html += """
                    </tbody>
                </table>
            </div>
"""

            # jQuery PP findings
            if jquery_findings:
                report_html += f"<h3>🎯 jQuery Prototype Pollution (CVE-2019-11358) ({len(jquery_findings)} found)</h3>"
                for idx, vuln in enumerate(jquery_findings, 1):
                    # Pre-calculate payload HTML to avoid backslashes/complex logic in f-strings
                    payload_raw = vuln.get('payload')
                    if payload_raw:
                        payload_display = str(payload_raw)
                        payload_has_div = f'<div class="payload-code" style="margin-top:5px; border-color:orange;">Has Payload: {html_escape(payload_display)}</div>'
                    else:
                        payload_display = "$.extend(true, {}, JSON.parse('{\"__proto__\": {\"devMode\": true}}'))"
                        payload_has_div = ""
                    
                    escaped_payload_display = html_escape(payload_display)
                    escaped_name = html_escape(vuln.get('name', 'Unknown'))
                    
                    report_html += f'''
            <div class="vulnerability">
                <strong>#{idx} - {escaped_name}</strong>
                <span class="method-label critical">{vuln.get('severity', 'CRITICAL')}</span><br>
                <strong>Payload:</strong><br>
                <div class="payload-code">{escaped_payload_display}</div>
                {payload_has_div}
                <div style="margin-top: 10px;">
                    <strong>Verification Steps:</strong>
                    <div class="verification">
                        1. Ensure jQuery version is < 3.5.0<br>
                        2. Test with provided payload above<br>
                        3. Check if prototype chain was polluted<br>
                        4. Look for unexpected behavior or data leakage
                    </div>
                </div>
            </div>
'''

            # XSS findings
            if xss_findings:
                report_html += f"<h3>⚡ Cross-Site Scripting (XSS) ({len(xss_findings)} found)</h3>"
                for idx, vuln in enumerate(xss_findings, 1):
                    param = vuln.get("param", "unknown")
                    payload = vuln.get("payload", "")

                    report_html += f"""
            <div class="vulnerability">
                <strong>#{idx} - XSS in Parameter: {html_escape(param)}</strong>
                <span class="method-label high">{vuln.get('severity', 'HIGH')}</span><br>
                <strong>Payload:</strong><br>
                <div class="payload-code">{html_escape(str(payload)[:200])}</div>
                <div style="margin-top: 10px;">
                    <strong>Verification:</strong>
                    <div class="verification">
                        Test URL with payload: {html_escape(target_url)}?{html_escape(param)}={html_escape(str(payload)[:100])}
                    </div>
                </div>
            </div>
"""

        report_html += """
        </div>
        
        <div class="section">
            <h2>📋 Recommendations & Remediation</h2>
            <ul>
"""

        if waf_bypasses:
            report_html += """
                <li><strong>WAF Bypass Prevention:</strong>
                    <ul>
                        <li>Implement multi-layer input validation (not just regex-based)</li>
                        <li>Use parameterized requests instead of string concatenation</li>
                        <li>Apply both normalized and original value checks</li>
                        <li>Monitor for bypass attempt patterns in logs</li>
                        <li>Regularly update WAF rules with new bypass techniques</li>
                        <li>Test WAF effectiveness against known bypass methods</li>
                    </ul>
                </li>
"""

        if jquery_findings:
            report_html += """
                <li><strong>jQuery Prototype Pollution:</strong>
                    <ul>
                        <li>Upgrade jQuery to version 3.5.0 or higher (patch released 2020-04-10)</li>
                        <li>Replace $.extend() with Object.assign() or object spread syntax</li>
                        <li>Implement strict input validation on all user-supplied parameters</li>
                        <li>Use allowlists for accepted object keys</li>
                        <li>Apply Content Security Policy (CSP) headers</li>
                        <li>Consider using Object.freeze() or Object.seal() on critical objects</li>
                    </ul>
                </li>
"""

        if xss_findings:
            report_html += """
                <li><strong>Cross-Site Scripting (XSS):</strong>
                    <ul>
                        <li>Implement proper output encoding (HTML, JavaScript, URL context-aware)</li>
                        <li>Use a templating engine with auto-escaping enabled</li>
                        <li>Set X-XSS-Protection header (defense in depth)</li>
                        <li>Implement Content Security Policy (CSP) with script-src restrictions</li>
                        <li>Use HTTPOnly and Secure flags on authentication cookies</li>
                        <li>Sanitize user input with a library like DOMPurify</li>
                        <li>Avoid using eval() and similar dangerous functions</li>
                    </ul>
                </li>
"""

        report_html += """
            </ul>
        </div>
        
        <div class="section">
            <h2>🔐 Security Testing Best Practices</h2>
            <ul>
                <li><strong>Validation:</strong> Always validate findings in a controlled environment with proper authorization</li>
                <li><strong>Reproduction:</strong> Document exact steps to reproduce each finding</li>
                <li><strong>Testing:</strong> Test on a copy of the application, not production</li>
                <li><strong>Documentation:</strong> Keep records of all testing activities</li>
                <li><strong>Remediation:</strong> Track fixes and verify them after deployment</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>⚖️ Disclaimer</h2>
            <p>This report was generated by PPMAP v4.4.2 for authorized security testing only.
            The findings should be validated and addressed by qualified security professionals.
            Always obtain proper authorization before performing security assessments on any target.
            Unauthorized access to computer systems is illegal.</p>
        </div>
        
        <footer>
            <p>PPMAP v4.4.2 | Prototype Pollution Multi-Purpose Assessment Platform</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
"""
        return report_html


# ============================================================================
# MAIN
# ============================================================================
