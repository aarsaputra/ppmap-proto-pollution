"""Data models representing scan metrics and complete reports."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
from ppmap.models.findings import Finding


@dataclass
class ScanMetrics:
    """Track scan performance metrics for reporting."""

    start_time: float = 0.0
    end_time: float = 0.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    payloads_tested: int = 0
    vulnerabilities_found: int = 0
    frameworks_detected: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Total scan duration in seconds."""
        return self.end_time - self.start_time if self.end_time else 0.0

    @property
    def requests_per_second(self) -> float:
        """Average requests per second."""
        if self.duration > 0:
            return self.total_requests / self.duration
        return 0.0

    @property
    def success_rate(self) -> float:
        """Percentage of successful requests."""
        if self.total_requests > 0:
            return (self.successful_requests / self.total_requests) * 100
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "duration_seconds": round(self.duration, 2),
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "requests_per_second": round(self.requests_per_second, 2),
            "success_rate_percent": round(self.success_rate, 2),
            "payloads_tested": self.payloads_tested,
            "vulnerabilities_found": self.vulnerabilities_found,
            "frameworks_detected": self.frameworks_detected,
        }


@dataclass
class ScanReport:
    """Represents complete scan report"""

    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    scanner_version: str = "4.1.0"
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
