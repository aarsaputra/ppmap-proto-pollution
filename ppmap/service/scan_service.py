"""
ppmap/service/scan_service.py — Service / Orchestrator Layer

This is the single entry-point between the CLI and the scanner modules.
The CLI (ppmap.py) should ONLY call run_scan() and get_summary().

Architecture:
    ppmap.py (CLI) → scan_service.run_scan() → scanner.tier* → models.*
"""

import logging
import time
from typing import List, Optional, Any

from ppmap.models.findings import Finding
from ppmap.models.reports import ScanMetrics, ScanReport
from ppmap.models.config import ScanConfig

logger = logging.getLogger(__name__)


class ScanSession:
    """
    Holds all state for a single scan session.
    Prevents scan state from leaking between calls.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.metrics = ScanMetrics(start_time=time.time())
        self.findings: List[Finding] = []
        self.report: Optional[ScanReport] = None


def run_scan(
    target_url: str,
    config: ScanConfig,
    request_data: Optional[Any] = None,
    run_discovery: bool = True,
) -> ScanSession:
    """
    Primary entry point for all scan operations.

    Args:
        target_url:     URL to scan
        config:         ScanConfig with timeout, stealth, oob_enabled, etc.
        request_data:   Optional parsed Burp request dict for SSPP injection
        run_discovery:  Whether to crawl endpoints before scanning

    Returns:
        ScanSession with .findings and .metrics populated
    """
    session = ScanSession(config)

    try:
        # Import here to keep top-level imports clean (no circular risk)
        from ppmap.scanner.core import CompleteSecurityScanner

        scanner = CompleteSecurityScanner(config=config)
        raw_findings = scanner.scan_target(
            target_url,
            request_data=request_data,
            run_discovery=run_discovery,
        )
        session.findings = raw_findings
    except Exception as e:
        logger.error(f"[scan_service] Scan failed for {target_url}: {e}")

    session.metrics.end_time = time.time()
    session.metrics.vulnerabilities_found = len(session.findings)
    return session


def run_batch_scan(
    targets: List[str],
    config: ScanConfig,
    max_workers: int = 3,
) -> List[ScanSession]:
    """
    Scan multiple targets concurrently (bounded by max_workers).

    Returns a list of ScanSessions, one per target.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    sessions = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run_scan, url, config): url for url in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                session = future.result()
                sessions.append(session)
                logger.info(
                    f"[batch] {target} → {len(session.findings)} findings"
                )
            except Exception as e:
                logger.error(f"[batch] {target} failed: {e}")

    return sessions
