"""Data models representing security scan findings."""

from enum import Enum
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, Any, Optional


class Severity(str, Enum):
    """Vulnerability severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    """Supported vulnerability types"""

    JQUERY_PP = "jquery_pp"
    XSS = "xss"
    POST_XSS = "post_xss"
    SERVER_SIDE_PP = "server_side_pp"
    WAF_BYPASS = "waf_bypass"
    CVE = "cve"
    ENDPOINT = "endpoint"
    FRAMEWORK = "framework"

    # Newer categories
    REACT_FLIGHT = "react_flight_vulnerability"
    BLIND_OOB = "blind_oob"
    BLIND_PP = "blind_pp_detected"
    PERSISTENT_PP = "persistent_pp"
    STATUS_OVERRIDE = "status_override_detected"
    FUNCP_POLLUTION = "function_prototype_pollution"
    SVELTEKIT_SUPERFORMS = "sveltekit_superforms_pollution"
    SVELTEKIT_URL = "sveltekit_url_pollution"
    CHARSET_OVERRIDE = "charset_override_detected"
    FETCH_API = "fetch_api_pollution"
    OBJECT_DP = "object_defineproperty_bypass"
    CHILD_PROCESS = "child_process_rce"
    CONSTRUCTOR = "constructor_pollution"
    SANITIZATION_BYPASS = "sanitization_bypass"
    THIRD_PARTY_GADGET = "third_party_gadget"
    DESCRIPTOR_POLLUTION = "descriptor_pollution"
    CORS_POLLUTION = "cors_header_pollution"
    STORAGE_API = "storage_api_pollution"
    KIBANA_RCE = "kibana_telemetry_rce"
    BLITZJS_RCE = "blitzjs_rce_chain"
    ELASTIC_XSS = "elastic_xss"


@dataclass
class Finding:
    """Represents a single security finding"""

    type: VulnerabilityType
    severity: Severity
    name: str
    description: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    confidence: float = 1.0  # 0.0 - 1.0
    verified: bool = False
    cve: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["type"] = self.type.value
        data["severity"] = self.severity.value
        data["discovered_at"] = self.discovered_at.isoformat()
        return data

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.type.value}: {self.name}"
