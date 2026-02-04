"""Data models and enums for PPMAP"""
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any, List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    JQUERY_PP = "jquery_pp"
    XSS = "xss"
    POST_XSS = "post_xss"
    SERVER_SIDE_PP = "server_side_pp"
    WAF_BYPASS = "waf_bypass"
    CVE = "cve"
    ENDPOINT = "endpoint"
    FRAMEWORK = "framework"


@dataclass
class Finding:
    type: VulnerabilityType
    severity: Severity
    name: str
    description: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    confidence: float = 1.0
    verified: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['type'] = self.type.value
        d['severity'] = self.severity.value
        d['discovered_at'] = self.discovered_at.isoformat()
        return d


@dataclass
class ScanReport:
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'findings': [f.to_dict() for f in self.findings]
        }
