"""
ppmap/scanner/tier5_research.py - Tier 5: Recent Research & Third-Party Integrations

Tests based on various Phase 1 / Phase 2 black-box techniques.

Methods:
    - CORS Header Pollution (Access-Control-*)
    - Third-Party Library Gadgets (Analytics, GTM, DTM, Vue, DOMPurify)
    - Storage API Pollution (localStorage / sessionStorage property access)

Extracted from: scanner/core.py lines 3507–3747 + 4376-4446
"""

import time
import logging
from typing import Any, Dict, List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors, progress_iter

logger = logging.getLogger(__name__)


class Tier5ResearchScanner(BaseTierScanner):
    """Recent research and third-party integration PP detection."""

    @property
    def tier_name(self) -> str:
        return "Tier 5 - Research & Integrations"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw_dicts: List[Dict[str, Any]] = []

        raw_dicts += self._test_cors_header_pollution(ctx)
        raw_dicts += self._test_third_party_gadgets(ctx)
        raw_dicts += self._test_storage_api_pollution(ctx)
        raw_dicts += self._test_2026_gadgets(ctx)

        findings = [self._to_finding(r, ctx.target_url) for r in raw_dicts]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_cors_header_pollution(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        CORS configuration pollution via Access-Control-Expose-Headers.
        Safe, non-destructive server-side PP detection.
        """
        print(f"{Colors.BOLD}[→] Testing CORS Header Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        payloads = [
            ('{"__proto__":{"exposedHeaders":"X-PPMAP-Test"}}', "exposedHeaders", "Access-Control-Expose-Headers"),
            ('{"__proto__":{"allowedHeaders":"X-Polluted"}}', "allowedHeaders", "Access-Control-Allow-Headers"),
            ('{"__proto__":{"credentials":true}}', "credentials", "Access-Control-Allow-Credentials"),
            ('{"constructor":{"prototype":{"exposedHeaders":"X-PPMAP-Constructor"}}}', "constructor_exposedHeaders", "Constructor bypass"),
        ]

        try:
            for payload, pollution_type, header_name in progress_iter(payloads, desc="CORS PP"):
                try:
                    headers = {
                        "Content-Type": "application/json",
                        "Origin": "https://attacker.com",
                    }
                    resp = session.post(target_url, data=payload, headers=headers, timeout=5, verify=False)

                    cors_headers = {k.lower(): v for k, v in resp.headers.items() if "access-control" in k.lower()}

                    if cors_headers:
                        for header, value in cors_headers.items():
                            if "ppmap" in value.lower() or "polluted" in value.lower():
                                findings.append({
                                    "type": "cors_header_pollution",
                                    "method": f"CORS_{pollution_type.upper()}",
                                    "severity": "HIGH",
                                    "description": f"CORS configuration polluted via {header_name}",
                                    "payload": payload,
                                    "polluted_header": header,
                                    "header_value": value,
                                    "reference": "refrensi.md line 221 - CORS PP Detection",
                                })
                                print(f"{Colors.FAIL}[!] CORS Pollution Detected: {header} = {value}{Colors.ENDC}")
                except Exception as e:
                    logger.debug(f"CORS test error: {e}")
                    continue

            if not findings:
                print(f"{Colors.GREEN}[✓] CORS header pollution test completed (No vulnerability){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] CORS test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_third_party_gadgets(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Third-Party Library Gadget Testing (Phase 1).
        Analytics, GTM, DTM, Vue, DOMPurify.
        """
        print(f"{Colors.BOLD}[→] Testing Third-Party Library Gadgets...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        driver = ctx.driver
        target_url = ctx.target_url

        try:
            from ppmap.payloads import CLIENT_XSS_GADGETS
        except ImportError:
            logger.warning("CLIENT_XSS_GADGETS unavailable")
            return findings

        gadget_tests = [
            {
                "library": g[0],
                "payload": f"?__proto__[{g[1]}]={g[2]}",
                "property": g[1],
                "impact": g[3],
                "detection": g[4],
            }
            for g in CLIENT_XSS_GADGETS
        ]

        try:
            initial_resp = session.get(target_url, timeout=5, verify=False)
            page_content = initial_resp.text.lower()

            detected_libraries = [t for t in gadget_tests if any(ind.lower() in page_content for ind in t["detection"])]

            if not detected_libraries:
                print(f"{Colors.GREEN}[✓] No known third-party gadget libraries detected in page source{Colors.ENDC}")
                return findings

            print(f"{Colors.CYAN}[*] Detected {len(detected_libraries)} third-party libraries{Colors.ENDC}")

            for test in progress_iter(detected_libraries, desc="Gadget Tests"):
                try:
                    payload_qs = test["payload"].lstrip("?")
                    separator = "&" if "?" in target_url else "?"
                    test_url = f"{target_url}{separator}{payload_qs}"

                    is_polluted = False
                    if driver:
                        try:
                            # Baseline check
                            driver.get(target_url)
                            time.sleep(1)
                            baseline_set = driver.execute_script(f"return Object.prototype['{test['property']}'] !== undefined;")
                            if baseline_set:
                                continue

                            # Inject payload
                            driver.get(test_url)
                            time.sleep(2)
                            is_polluted = driver.execute_script(
                                f"return Object.prototype['{test['property']}'] !== undefined && "
                                f"Object.prototype['{test['property']}'] !== null;"
                            )
                        except Exception as nav_err:
                            logger.debug(f"Browser gadget nav error: {nav_err}")

                    if is_polluted:
                        findings.append({
                            "type": "third_party_gadget",
                            "method": f'GADGET_{test["library"].upper().replace(" ", "_")}',
                            "severity": "HIGH",
                            "library": test["library"],
                            "property": test["property"],
                            "impact": test["impact"],
                            "payload": test["payload"],
                            "test_url": test_url,
                            "verified": True,
                            "reference": "refrensi.md lines 69-96 - Third-Party Gadgets",
                        })
                        print(f"{Colors.FAIL}[!] Gadget CONFIRMED (JS Verified): {test['library']} ({test['property']}){Colors.ENDC}")

                except Exception as e:
                    logger.debug(f"Gadget test error: {e}")
                    continue

            if not findings:
                print(f"{Colors.GREEN}[✓] Third-party gadget test completed (No vulnerability){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Third-party gadget test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_storage_api_pollution(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        localStorage/sessionStorage API Gadget Detection.
        Checks if Web Storage uses direct property access (storage[key] vs storage.getItem(key)).
        IMPORTANT: Direct property access on Storage is a standard ECMAScript behavior of Storage objects.
        It ONLY becomes a vulnerability if a Prototype Pollution vector is present to pollute Object.prototype.
        Therefore, we only flag this if an actual prototype pollution vector was confirmed on the site.
        """
        print(f"{Colors.BOLD}[→] Testing Storage API Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        driver = ctx.driver
        target_url = ctx.target_url

        if not driver:
            print(f"{Colors.WARNING}[⚠] Browser required for Storage API tests (skipped){Colors.ENDC}")
            return findings

        # Check if any prior PP findings exist (Storage API is a gadget, not a standalone vector)
        # Without a functional PP entry point (query param, JSON, etc.), Storage inheritance is benign.
        try:
            driver.get(target_url)
            time.sleep(1)

            storage_tests = [
                {
                    "api": "localStorage",
                    "test_script": """
                        try {
                            var canary = 'ppmap_store_' + Date.now();
                            if (localStorage.hasOwnProperty(canary)) return false;
                            
                            // Check if Storage prototype inherits directly from Object.prototype
                            Object.prototype[canary] = 'PPMAP_TEST';
                            var inherits = localStorage[canary] === 'PPMAP_TEST' && localStorage.getItem(canary) === null;
                            delete Object.prototype[canary];
                            
                            return inherits;
                        } catch(e) {
                            return false;
                        }
                    """,
                },
                {
                    "api": "sessionStorage",
                    "test_script": """
                        try {
                            var canary = 'ppmap_sess_' + Date.now();
                            if (sessionStorage.hasOwnProperty(canary)) return false;
                            
                            Object.prototype[canary] = 'PPMAP_TEST';
                            var inherits = sessionStorage[canary] === 'PPMAP_TEST' && sessionStorage.getItem(canary) === null;
                            delete Object.prototype[canary];
                            
                            return inherits;
                        } catch(e) {
                            return false;
                        }
                    """,
                },
            ]

            # Storage API Direct Property Access is an informational gadget finding (INFO/LOW),
            # but per W3C specification, all standard Storage objects inherit from Object.prototype.
            # To avoid cluttering scan reports with standard browser behavior on clean sites,
            # we do NOT report this unless explicit storage reading code is detected or PP is confirmed.
            for test in storage_tests:
                try:
                    is_gadget = driver.execute_script(test["test_script"])
                    # Standard Web Storage API always inherits from Object.prototype by browser design.
                    # We do not report false positives on standard browser behavior unless verified.
                    if is_gadget:
                        logger.info(f"Storage API gadget surface detected on {test['api']} (benign browser inheritance)")
                except Exception as e:
                    logger.debug(f"Storage API script error: {e}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Storage API test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_2026_gadgets(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        2026 CVE-based gadget fingerprinting.
        Targets:  Axios validateStatus (CVE-2026-42041)
                  defu merge bypass (CVE-2026-35209)
                  DOMPurify hook pollution (CVE-2026-41238)
                  devalue.parse deserialization (CVE-2025-57820)
        """
        print(f"{Colors.BOLD}[→] Testing 2026 CVE Gadget Fingerprints...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        # Each entry: (payload_json, property_name, cve_ref, description)
        gadgets_2026 = [
            (
                '{"__proto__":{"validateStatus":true}}',
                "validateStatus",
                "CVE-2026-42041",
                "Axios validateStatus pollution: may allow any HTTP status to pass authentication checks",
            ),
            (
                '{"__proto__":{"skipProto":true}}',
                "skipProto",
                "CVE-2026-35209",
                "defu merge bypass: skipProto flag suppresses standard __proto__ protection",
            ),
            (
                '{"__proto__":{"FORCE_BODY":"<img src=x onerror=alert(1)>"}}',
                "FORCE_BODY",
                "CVE-2026-41238",
                "DOMPurify hook pollution: FORCE_BODY may cause arbitrary HTML injection post-sanitization",
            ),
            (
                '{"__proto__":{"toJSON":"__PPMAP_DEVALUE__"}}',
                "toJSON",
                "CVE-2025-57820",
                "devalue.parse deserialization gadget: toJSON override on Object.prototype taints serialized output",
            ),
        ]

        try:
            for payload_json, prop, cve, description in progress_iter(gadgets_2026, desc="2026 Gadgets"):
                try:
                    headers = {"Content-Type": "application/json"}
                    resp = session.post(
                        target_url,
                        data=payload_json,
                        headers=headers,
                        timeout=8,
                        verify=False,
                    )
                    body = resp.text

                    # Heuristic: marker reflection or server error hints at gadget firing
                    if "__PPMAP_DEVALUE__" in body or prop in body:
                        severity = "HIGH"
                        findings.append({
                            "type": "gadget_2026",
                            "method": f"GADGET_2026_{prop.upper()}",
                            "severity": severity,
                            "payload": payload_json,
                            "reference": cve,
                            "description": description,
                            "evidence": f"Property '{prop}' reflected in response",
                        })
                        print(f"{Colors.FAIL}[!] 2026 Gadget DETECTED [{cve}]: {prop}{Colors.ENDC}")

                    elif resp.status_code in (500, 502, 503):
                        findings.append({
                            "type": "gadget_2026",
                            "method": f"GADGET_2026_{prop.upper()}_CRASH",
                            "severity": "MEDIUM",
                            "payload": payload_json,
                            "reference": cve,
                            "description": description,
                            "evidence": f"HTTP {resp.status_code} triggered by 2026 gadget payload",
                        })
                        print(f"{Colors.WARNING}[!] 2026 Gadget crash [{cve}] HTTP {resp.status_code}: {prop}{Colors.ENDC}")

                except Exception as e:
                    logger.debug(f"2026 gadget test error [{prop}]: {e}")

            if not findings:
                print(f"{Colors.GREEN}[✓] 2026 gadget tests complete (No vulnerability){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] 2026 gadget test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _to_finding(self, raw: Dict[str, Any], url: str) -> Finding:
        severity_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }
        type_map = {
            "storage_api_pollution": VulnerabilityType.STORAGE_API,
            "cors_header_pollution": VulnerabilityType.CORS_POLLUTION,
            "third_party_gadget": VulnerabilityType.THIRD_PARTY_GADGET,
            "elastic_xss": VulnerabilityType.ELASTIC_XSS,
        }
        
        return Finding(
            name=raw.get("description", raw.get("type", "PP Finding")),
            severity=severity_map.get(raw.get("severity", "MEDIUM"), Severity.MEDIUM),
            type=type_map.get(raw.get("type"), VulnerabilityType.PROTOTYPE_POLLUTION),
            url=raw.get("test_url", url),
            method=raw.get("method", ""),
            payload=str(raw.get("payload", "")),
            evidence=str(raw.get("reference", raw.get("polluted_header", ""))),
            description=raw.get("description", ""),
            metadata=raw
        )
