"""
ppmap/scanner/base.py - Shared base interface for all tier scanners.

Every tier module MUST subclass BaseTierScanner and implement:
    - run(ctx: ScanContext) -> List[Finding]
    - tier_name (property)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ppmap.models.findings import Finding

if TYPE_CHECKING:
    # Avoid circular imports at runtime; only used for type hints
    import requests

logger = logging.getLogger(__name__)


# ============================================================================
# SHARED SCAN CONTEXT
# ============================================================================


@dataclass
class ScanContext:
    """Immutable-ish state container passed to every tier.

    Attributes:
        target_url:  The URL being scanned (normalized).
        driver:      Selenium WebDriver instance (may be None in headless-off runs).
        session:     requests.Session with stealth/auth headers pre-configured.
        config:      ScanConfig instance from ppmap.models.config.
        page_source: Cached HTML source of the target page (populated on first load).
        js_files:    List of discovered external JS file URLs.
        findings:    Shared accumulator — tiers may append to this list.
        meta:        Arbitrary key-value store for passing runtime hints between tiers
                     (e.g., {'waf_detected': 'Cloudflare', 'jquery_version': '3.3.1'}).
    """

    target_url: str
    driver: Any = None               # selenium WebDriver or None
    session: Any = None              # requests.Session or None
    config: Any = None               # ScanConfig instance
    request_data: Optional[Dict[str, Any]] = None  # Burp suite request override data
    page_source: str = ""
    js_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def set_meta(self, key: str, value: Any) -> None:
        """Store a runtime hint for downstream tiers."""
        self.meta[key] = value

    def get_meta(self, key: str, default: Any = None) -> Any:
        """Retrieve a runtime hint set by an earlier tier."""
        return self.meta.get(key, default)


# ============================================================================
# BASE TIER SCANNER
# ============================================================================


class BaseTierScanner(ABC):
    """Abstract base class — contract that every tier module must fulfil.

    Usage::

        class Tier1BlindScanner(BaseTierScanner):
            @property
            def tier_name(self):
                return "Tier 1 - Blind Detection"

            def run(self, ctx: ScanContext) -> List[Finding]:
                findings = []
                findings += self._test_json_spaces_overflow(ctx)
                # ...
                return findings
    """

    def __init__(self):
        self.logger = logging.getLogger(f"ppmap.tier.{self.__class__.__name__}")

    # ── Public API (must implement) ──────────────────────────

    @property
    @abstractmethod
    def tier_name(self) -> str:
        """Human-readable tier label, e.g. 'Tier 1 - Blind Detection'."""
        ...

    @abstractmethod
    def run(self, ctx: ScanContext) -> List[Finding]:
        """Execute all tests for this tier.

        Args:
            ctx: Shared ScanContext with driver, session, config, and target URL.

        Returns:
            List of verified Finding objects. Must NOT include unconfirmed results.
        """
        ...

    # ── Helper utilities available to all tiers ──────────────

    def log_start(self, ctx: ScanContext) -> None:
        self.logger.info(f"[→] {self.tier_name}: {ctx.target_url}")

    def log_clean(self) -> None:
        self.logger.debug(f"[✓] {self.tier_name}: No vulnerabilities detected")

    def log_finding(self, finding: Finding) -> None:
        symbol = "🔴" if finding.severity.value >= 7 else "🟡"
        self.logger.warning(f"[!] {symbol} {self.tier_name}: {finding.name} [{finding.severity.name}]")
