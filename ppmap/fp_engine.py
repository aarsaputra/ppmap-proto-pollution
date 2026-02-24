"""
False Positive Reduction Engine for PPMAP v5.0
Provides secondary verification and confidence scoring to reduce false positives.
"""
import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """Status of secondary verification."""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"
    SKIPPED = "skipped"


@dataclass
class VerificationResult:
    """Result of secondary verification."""
    status: VerificationStatus
    confidence: float  # 0.0 - 1.0
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class FalsePositiveEngine:
    """
    Engine to reduce false positives through:
    1. Reflected parameter detection
    2. Secondary browser verification
    3. Confidence scoring based on multiple signals
    4. Context-aware validation
    """
    
    # Known patterns that indicate reflection without pollution
    REFLECTION_PATTERNS = [
        r'name=["\']?{param}["\']?',
        r'value=["\']?{value}["\']?',
        r'placeholder=["\']?.*{param}.*["\']?',
        r'data-.*=["\']?{value}["\']?',
        r'<input[^>]*{param}[^>]*>',
        r'<option[^>]*{value}[^>]*>',
    ]
    
    # Patterns that suggest genuine pollution
    POLLUTION_INDICATORS = [
        r'Object\.prototype\.',
        r'__proto__',
        r'constructor\.prototype',
        r'polluted["\']?\s*[:=]\s*["\']?true',
        r'isAdmin["\']?\s*[:=]\s*["\']?true',
    ]
    
    # High-confidence gadget properties
    HIGH_CONFIDENCE_PROPS = {
        'shell', 'exec', 'command', 'cmd', 'code', 'eval',
        'NODE_OPTIONS', 'env', 'argv0', 'execArgv',
        'template', 'outputFunctionName', 'escapeFunction'
    }
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize FP Engine.
        
        Args:
            strict_mode: If True, require stronger evidence for confirmation
        """
        self.strict_mode = strict_mode
        self._cache: Dict[str, VerificationResult] = {}
    
    def is_reflected_param(self, response_text: str, param: str, value: str) -> bool:
        """
        Check if parameter is simply reflected without actual pollution.
        
        Args:
            response_text: HTTP response body
            param: Parameter name being tested
            value: Parameter value sent
            
        Returns:
            True if param appears to be only reflected (not polluted)
        """
        if not response_text or not param:
            return False
        
        # Count occurrences of value in response
        value_count = response_text.lower().count(value.lower()) if value else 0
        
        # Check for reflection patterns
        for pattern in self.REFLECTION_PATTERNS:
            regex = pattern.format(param=re.escape(param), value=re.escape(str(value)))
            if re.search(regex, response_text, re.IGNORECASE):
                # Check if there are pollution indicators too
                has_pollution = any(
                    re.search(p, response_text, re.IGNORECASE) 
                    for p in self.POLLUTION_INDICATORS
                )
                if not has_pollution:
                    logger.debug(f"Detected reflection pattern for param '{param}'")
                    return True
        
        # If value appears many times, likely just echoed
        if value_count > 5 and len(value) > 3:
            logger.debug(f"Value '{value}' appears {value_count} times - likely reflection")
            return True
        
        return False
    
    def secondary_verify(self, finding: Dict, driver: Optional[Any] = None) -> VerificationResult:
        """
        Perform secondary verification of a finding using browser.
        
        Args:
            finding: The vulnerability finding dict
            driver: Optional browser driver for JS verification
            
        Returns:
            VerificationResult with status and confidence
        """
        finding_type = finding.get('type', finding.get('name', 'unknown'))
        cache_key = f"{finding_type}:{finding.get('url', '')}:{finding.get('payload', '')}"
        
        # Check cache
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        result = self._perform_verification(finding, driver)
        self._cache[cache_key] = result
        
        return result
    
    def _perform_verification(self, finding: Dict, driver: Optional[Any]) -> VerificationResult:
        """Internal verification logic."""
        finding_type = finding.get('type', finding.get('name', 'unknown')).lower()
        
        # BUG-10 FIX: CVE findings based only on version string (not browser-verified)
        # should NOT be auto-confirmed at 0.95. Split into two cases:
        # 1. CVE + browser-verified => CONFIRMED 0.95
        # 2. CVE + version-only => LIKELY 0.80 (still high, but not overclaiming)
        if 'cve' in finding:
            if finding.get('verified', False):
                return VerificationResult(
                    status=VerificationStatus.CONFIRMED,
                    confidence=0.95,
                    reason="CVE-based detection with browser-verified exploitation",
                    evidence={'cve': finding.get('cve'), 'browser_verified': True}
                )
            else:
                return VerificationResult(
                    status=VerificationStatus.LIKELY,
                    confidence=0.80,
                    reason="CVE-based detection from version string (not browser-verified)",
                    evidence={'cve': finding.get('cve'), 'version_only': True}
                )
        # Browser-verified findings
        if finding.get('verified', False):
            return VerificationResult(
                status=VerificationStatus.CONFIRMED,
                confidence=0.9,
                reason="Browser execution confirmed pollution",
                evidence={'browser_verified': True}
            )
        
        # Check for high-confidence gadget properties
        polluted_prop = finding.get('property', finding.get('polluted_property', ''))
        if polluted_prop in self.HIGH_CONFIDENCE_PROPS:
            return VerificationResult(
                status=VerificationStatus.LIKELY,
                confidence=0.8,
                reason=f"High-risk gadget property '{polluted_prop}' detected",
                evidence={'gadget_property': polluted_prop}
            )
        
        # Persistence findings are high confidence
        if 'persist' in finding_type or 'cross_request' in finding_type:
            return VerificationResult(
                status=VerificationStatus.LIKELY,
                confidence=0.85,
                reason="Cross-request persistence indicates real pollution",
                evidence={'persistence': True}
            )
        
        # Response-only findings need more scrutiny
        if not driver:
            return VerificationResult(
                status=VerificationStatus.UNCERTAIN,
                confidence=0.5,
                reason="No browser verification available",
                evidence={'response_only': True}
            )
        
        # Attempt browser verification
        try:
            url = finding.get('url', '')
            if url and driver:
                driver.get(url)
                
                # Check for actual prototype pollution
                check_script = """
                return {
                    polluted: Object.prototype.polluted === true,
                    isAdmin: Object.prototype.isAdmin === true,
                    hasCustomProp: Object.keys(Object.prototype).some(k => 
                        !['constructor', 'hasOwnProperty', 'toString', 'valueOf'].includes(k)
                    )
                };
                """
                result = driver.execute_script(check_script)
                
                if result.get('polluted') or result.get('isAdmin'):
                    return VerificationResult(
                        status=VerificationStatus.CONFIRMED,
                        confidence=0.95,
                        reason="Browser confirmed Object.prototype pollution",
                        evidence=result
                    )
                elif result.get('hasCustomProp'):
                    return VerificationResult(
                        status=VerificationStatus.LIKELY,
                        confidence=0.7,
                        reason="Unusual properties on Object.prototype",
                        evidence=result
                    )
        except Exception as e:
            logger.debug(f"Browser verification failed: {e}")
        
        return VerificationResult(
            status=VerificationStatus.UNCERTAIN,
            confidence=0.4,
            reason="Could not confirm with browser verification",
            evidence={}
        )
    
    def calculate_confidence(self, finding: Dict, evidence: Dict = None) -> float:
        """
        Calculate overall confidence score for a finding.
        
        Args:
            finding: The vulnerability finding
            evidence: Additional evidence dict
            
        Returns:
            Confidence score 0.0 - 1.0
        """
        score = 0.5  # Base score
        evidence = evidence or {}
        
        # Boost for CVE match
        if finding.get('cve'):
            score += 0.3
        
        # Boost for browser verification
        if finding.get('verified'):
            score += 0.25
        
        # Boost for persistence
        if 'persist' in finding.get('type', '').lower():
            score += 0.2
        
        # Boost for high-risk severity
        severity = finding.get('severity', '').upper()
        if severity == 'CRITICAL':
            score += 0.1
        elif severity == 'HIGH':
            score += 0.05
        
        # Penalty for reflection-only
        if evidence.get('reflected_only'):
            score -= 0.3
        
        # Penalty for no browser verification
        if evidence.get('response_only'):
            score -= 0.15
        
        # Clamp to valid range
        return max(0.0, min(1.0, score))
    
    def filter_findings(self, findings: List[Dict], 
                        min_confidence: float = 0.5,
                        driver: Optional[Any] = None) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter findings to reduce false positives.
        
        Args:
            findings: List of vulnerability findings
            min_confidence: Minimum confidence threshold (0.0-1.0)
            driver: Optional browser driver for verification
            
        Returns:
            Tuple of (confirmed_findings, filtered_out_findings)
        """
        confirmed = []
        filtered_out = []
        
        for finding in findings:
            # Perform secondary verification
            verification = self.secondary_verify(finding, driver)
            
            # Add verification info to finding
            finding['fp_verification'] = {
                'status': verification.status.value,
                'confidence': verification.confidence,
                'reason': verification.reason
            }
            
            # Calculate overall confidence
            confidence = self.calculate_confidence(finding, verification.evidence)
            finding['confidence_score'] = confidence
            
            # Filter based on threshold
            if confidence >= min_confidence:
                if verification.status != VerificationStatus.FALSE_POSITIVE:
                    confirmed.append(finding)
                else:
                    filtered_out.append(finding)
            else:
                filtered_out.append(finding)
        
        logger.info(f"FP Engine: {len(confirmed)} confirmed, {len(filtered_out)} filtered")
        
        return confirmed, filtered_out
    
    def validate_jquery_detection(self, version: str, response_text: str) -> VerificationResult:
        """
        Validate jQuery version detection accuracy.
        
        Args:
            version: Detected jQuery version
            response_text: Page content
            
        Returns:
            VerificationResult
        """
        if not version:
            return VerificationResult(
                status=VerificationStatus.SKIPPED,
                confidence=0.0,
                reason="No version detected"
            )
        
        # Check for jQuery patterns in response
        jquery_patterns = [
            rf'jquery[.-]?{re.escape(version)}',
            rf'jQuery\s+v{re.escape(version)}',
            rf'jquery\.min\.js\?v={re.escape(version)}',
        ]
        
        matches = sum(1 for p in jquery_patterns if re.search(p, response_text, re.IGNORECASE))
        
        if matches >= 1:
            return VerificationResult(
                status=VerificationStatus.CONFIRMED,
                confidence=0.9,
                reason=f"jQuery {version} confirmed in page source",
                evidence={'pattern_matches': matches}
            )
        
        return VerificationResult(
            status=VerificationStatus.UNCERTAIN,
            confidence=0.5,
            reason="Version detected via JS but not confirmed in source"
        )


# Singleton instance for easy access
_fp_engine: Optional[FalsePositiveEngine] = None


def get_fp_engine(strict_mode: bool = True) -> FalsePositiveEngine:
    """Get or create FP Engine singleton."""
    global _fp_engine
    if _fp_engine is None:
        _fp_engine = FalsePositiveEngine(strict_mode=strict_mode)
    return _fp_engine
