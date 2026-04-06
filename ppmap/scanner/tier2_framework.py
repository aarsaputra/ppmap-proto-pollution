"""
ppmap/scanner/tier2_framework.py - Tier 2: Modern Framework Prototype Pollution

Tests for PP vectors in contemporary JavaScript frameworks and encoding bypasses.

Methods:
    - React 19 / Next.js Flight Protocol (RESEARCH-2024-REACT-FLIGHT)
    - SvelteKit / Superforms (RESEARCH-2024-SVELTEKIT-RCE / RESEARCH-2024-DEVALUE)
    - Charset Override (UTF-7, ISO-2022-JP)

Extracted from: scanner/core.py lines 2552–2835
"""

import re
import time
import logging
from typing import Any, Dict, List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors

logger = logging.getLogger(__name__)


class Tier2FrameworkScanner(BaseTierScanner):
    """Modern framework and encoding-based Prototype Pollution detection."""

    @property
    def tier_name(self) -> str:
        return "Tier 2 - Modern Frameworks"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw: List[Dict[str, Any]] = []

        raw += self._test_react_flight_protocol(ctx)
        raw += self._test_sveltekit_superforms(ctx)
        raw += self._test_charset_override(ctx)

        findings = [self._to_finding(r, ctx.target_url) for r in raw]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_react_flight_protocol(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test React 19/Next.js Flight Protocol for PP vulnerability.
        RESEARCH-2024-REACT-FLIGHT, RESEARCH-2024-NEXTJS-FLIGHT
        """
        print(f"{Colors.CYAN}[→] Testing React 19/Next.js Flight Protocol...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            from ppmap.payloads.advanced import get_react_flight_payloads
            react_payloads = get_react_flight_payloads()

            for category, payloads in react_payloads.items():
                for payload in payloads[:2]:
                    try:
                        if not isinstance(payload, str):
                            continue
                        if not (payload.startswith("[") or payload.startswith("{")):
                            continue

                        headers = {
                            "Content-Type": "application/json",
                            "X-React-Flight": "true",
                        }
                        resp = session.post(target_url, data=payload, headers=headers,
                                            timeout=5, verify=False)

                        if resp.status_code >= 400:
                            continue

                        is_flight = False
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "text/x-component" in ct:
                            is_flight = True
                        if re.search(r'^\d+:[\[I"{]', resp.text) or re.search(r'\n\d+:[\[I"{]', resp.text):
                            is_flight = True

                        if is_flight and any(k in resp.text.lower()
                                             for k in ["constructor", "function", "child_process"]):
                            findings.append({
                                "type": "react_flight_vulnerability",
                                "method": f"FLIGHT_{category.upper()}",
                                "severity": "CRITICAL",
                                "description": f"React Flight Protocol vulnerable to {category}",
                                "payload": payload[:100],
                                "cve": "RESEARCH-2024-REACT-FLIGHT / RESEARCH-2024-NEXTJS-FLIGHT",
                            })
                            print(f"{Colors.FAIL}[!] CRITICAL: React Flight Protocol vulnerable!{Colors.ENDC}")
                            return findings
                    except Exception:
                        pass

            print(f"{Colors.GREEN}[✓] React Flight Protocol test completed{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] React Flight test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_sveltekit_superforms(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test SvelteKit/Superforms for prototype pollution.
        RESEARCH-2024-SVELTEKIT-RCE, RESEARCH-2024-DEVALUE
        """
        print(f"{Colors.CYAN}[→] Testing SvelteKit/Superforms for PP...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            from ppmap.payloads.advanced import get_sveltekit_payloads
            sveltekit_payloads = get_sveltekit_payloads()
            marker = f"svelte_{int(time.time())}"

            for category, payloads in sveltekit_payloads.items():
                for payload in payloads[:2]:
                    try:
                        if not ("__superform" in payload or "devalue" in payload
                                or "nodemailer" in payload.lower()):
                            continue

                        test_payload = payload.replace("true", f'"{marker}"')
                        resp = session.post(target_url, data=test_payload,
                                            headers={"Content-Type": "application/json"},
                                            timeout=5, verify=False)

                        if "sendmail" in resp.text or marker in resp.text:
                            severity = "CRITICAL" if "sendmail" in resp.text else "HIGH"
                            findings.append({
                                "type": "sveltekit_superforms_pollution",
                                "method": f"SVELTEKIT_{category.upper()}",
                                "severity": severity,
                                "description": f"SvelteKit/Superforms {category} PP detected",
                                "payload": payload[:100],
                                "cve": "RESEARCH-2024-SVELTEKIT-RCE",
                            })
                            print(f"{Colors.WARNING}[!] {severity}: SvelteKit/Superforms vulnerable!{Colors.ENDC}")

                        if isinstance(payload, str) and not payload.startswith("{"):
                            url_param = f"?__superform_data={payload[:50]}"
                            resp2 = session.get(target_url + url_param, timeout=5, verify=False)
                            if resp2.status_code < 400 and "__proto__" in resp2.text:
                                findings.append({
                                    "type": "sveltekit_url_pollution",
                                    "method": "SVELTEKIT_URL_FORM",
                                    "severity": "HIGH",
                                    "description": "SvelteKit form parameter PP",
                                    "payload": url_param,
                                    "cve": "RESEARCH-2024-SVELTEKIT-RCE",
                                })
                    except Exception:
                        pass

            if not findings:
                print(f"{Colors.GREEN}[✓] SvelteKit/Superforms test completed{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] SvelteKit test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_charset_override(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test for charset override attacks (UTF-7, ISO-2022, double encoding).
        Can bypass WAF filters and enable PP exploitation.
        """
        print(f"{Colors.CYAN}[→] Testing charset override attacks...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            from ppmap.payloads.advanced import get_charset_payloads
            charset_payloads = get_charset_payloads()

            charset_tests = [
                ("utf7_encoding", "application/json; charset=utf-7", "UTF7_BYPASS", "HIGH", "UTF-7"),
                ("iso_2022_bypass", "application/json; charset=iso-2022-jp", "ISO2022_BYPASS", "MEDIUM", "ISO-2022-JP"),
            ]

            for key, content_type, method, severity, encoding in charset_tests:
                for payload in charset_payloads.get(key, [])[:2]:
                    try:
                        resp = session.post(target_url, data=payload,
                                            headers={"Content-Type": content_type,
                                                     "Accept-Charset": encoding.lower()},
                                            timeout=5, verify=False)
                        if resp.status_code < 400 and "PPMAP_CHARSET" in resp.text:
                            findings.append({
                                "type": "charset_override_detected",
                                "method": method,
                                "severity": severity,
                                "description": f"{encoding} charset override detected - can bypass WAF",
                                "payload": payload[:80],
                                "encoding": encoding,
                            })
                            print(f"{Colors.WARNING}[!] {severity}: {encoding} charset bypass detected!{Colors.ENDC}")
                            break
                    except Exception:
                        pass

            if not findings:
                print(f"{Colors.GREEN}[✓] Charset override test completed{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Charset override test error: {str(e)[:80]}{Colors.ENDC}")

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
            url=url,
            method=raw.get("method", ""),
            payload=str(raw.get("payload", "")),
            evidence=str(raw.get("cve", raw.get("encoding", ""))),
            description=raw.get("description", ""),
        )
