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
        localStorage/sessionStorage API Pollution via direct property access.
        """
        print(f"{Colors.BOLD}[→] Testing Storage API Pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        driver = ctx.driver
        target_url = ctx.target_url

        if not driver:
            print(f"{Colors.WARNING}[⚠] Browser required for Storage API tests (skipped){Colors.ENDC}")
            return findings

        try:
            driver.get(target_url)
            time.sleep(1)

            storage_tests = [
                {
                    "api": "localStorage",
                    "test_script": """
                        Object.prototype.testItem = 'PPMAP_POLLUTED';
                        var directAccess = localStorage.testItem;
                        var safeAccess = localStorage.getItem('testItem');
                        delete Object.prototype.testItem;
                        return { vulnerable: directAccess === 'PPMAP_POLLUTED', directValue: directAccess, safeValue: safeAccess };
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
                    result = driver.execute_script(test["test_script"])
                    is_vuln = result.get("vulnerable") if isinstance(result, dict) else result

                    if is_vuln:
                        findings.append({
                            "type": "storage_api_pollution",
                            "method": f'STORAGE_{test["api"].upper()}',
                            "severity": "MEDIUM",
                            "api": test["api"],
                            "description": f'{test["api"]} vulnerable to direct property access',
                            "reference": "refrensi.md line 98 - Storage API Gadgets",
                        })
                        print(f"{Colors.WARNING}[!] {test['api']} pollution detected{Colors.ENDC}")
                except Exception as e:
                    logger.debug(f"Storage API script error: {e}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Storage API test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_finding(raw: Dict[str, Any], url: str) -> Finding:
        severity_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }
        return Finding(
            name=raw.get("description", raw.get("type", "PP Finding")),
            severity=severity_map.get(raw.get("severity", "MEDIUM"), Severity.MEDIUM),
            type=VulnerabilityType.PROTOTYPE_POLLUTION,
            url=raw.get("test_url", url),
            method=raw.get("method", ""),
            payload=str(raw.get("payload", "")),
            evidence=str(raw.get("reference", raw.get("polluted_header", ""))),
            description=raw.get("description", ""),
        )
