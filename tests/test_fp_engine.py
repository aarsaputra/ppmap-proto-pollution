"""
Unit tests for False Positive Reduction Engine
"""
import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.fp_engine import (
    FalsePositiveEngine, 
    VerificationStatus, 
    VerificationResult,
    get_fp_engine
)


class TestFalsePositiveEngine:
    """Test suite for FalsePositiveEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create FP Engine instance."""
        return FalsePositiveEngine(strict_mode=True)
    
    @pytest.fixture
    def sample_finding(self):
        """Sample vulnerability finding."""
        return {
            'type': 'prototype_pollution',
            'url': 'http://example.com/test?__proto__[polluted]=true',
            'severity': 'HIGH',
            'property': 'polluted',
            'payload': '{"__proto__": {"polluted": true}}'
        }
    
    @pytest.fixture
    def cve_finding(self):
        """Sample CVE-based finding."""
        return {
            'type': 'jquery_pp',
            'cve': 'CVE-2019-11358',
            'name': 'Prototype Pollution in jQuery $.extend()',
            'severity': 'CRITICAL',
            'jquery_version': '3.4.1'
        }


class TestIsReflectedParam:
    """Tests for is_reflected_param method."""
    
    def test_reflected_in_input_value(self):
        """Parameter reflected in input value should be detected."""
        engine = FalsePositiveEngine()
        response = '<input type="text" name="search" value="test_value">'
        
        result = engine.is_reflected_param(response, 'search', 'test_value')
        assert result is True
    
    def test_reflected_in_placeholder(self):
        """Parameter reflected in placeholder should be detected."""
        engine = FalsePositiveEngine()
        response = '<input placeholder="Enter search term">'
        
        result = engine.is_reflected_param(response, 'search', 'term')
        # Should return True because 'search' is in placeholder
        assert result is True
    
    def test_not_reflected_with_pollution(self):
        """Should NOT mark as reflected if pollution indicators present."""
        engine = FalsePositiveEngine()
        response = '''
        <script>
        Object.prototype.polluted = true;
        var data = {"__proto__": {"isAdmin": true}};
        </script>
        <input name="test" value="test_value">
        '''
        
        result = engine.is_reflected_param(response, 'test', 'test_value')
        assert result is False  # Pollution indicators override reflection
    
    def test_multiple_occurrences(self):
        """Value appearing many times suggests reflection."""
        engine = FalsePositiveEngine()
        response = 'value ' * 10  # 'value' appears 10 times
        
        result = engine.is_reflected_param(response, 'param', 'value')
        assert result is True
    
    def test_empty_response(self):
        """Empty response should not cause errors."""
        engine = FalsePositiveEngine()
        
        result = engine.is_reflected_param('', 'param', 'value')
        assert result is False
    
    def test_empty_param(self):
        """Empty param should not cause errors."""
        engine = FalsePositiveEngine()
        
        result = engine.is_reflected_param('<html>test</html>', '', 'value')
        assert result is False


class TestSecondaryVerify:
    """Tests for secondary_verify method."""
    
    def test_cve_finding_confirmed(self):
        """CVE findings should be automatically confirmed."""
        engine = FalsePositiveEngine()
        finding = {'cve': 'CVE-2019-11358', 'type': 'jquery_pp'}
        
        result = engine.secondary_verify(finding)
        
        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence >= 0.9
    
    def test_browser_verified_finding(self):
        """Browser-verified findings should be confirmed."""
        engine = FalsePositiveEngine()
        finding = {'type': 'dom_pp', 'verified': True}
        
        result = engine.secondary_verify(finding)
        
        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence >= 0.9
    
    def test_high_confidence_gadget(self):
        """High-risk gadget properties should be marked likely."""
        engine = FalsePositiveEngine()
        finding = {'type': 'sspp', 'property': 'shell'}
        
        result = engine.secondary_verify(finding)
        
        assert result.status == VerificationStatus.LIKELY
        assert result.confidence >= 0.7
    
    def test_persistence_finding(self):
        """Persistence findings should be high confidence."""
        engine = FalsePositiveEngine()
        finding = {'type': 'persistent_prototype_pollution'}
        
        result = engine.secondary_verify(finding)
        
        assert result.status == VerificationStatus.LIKELY
        assert result.confidence >= 0.8
    
    def test_no_driver_uncertain(self):
        """Without driver, non-CVE findings should be uncertain."""
        engine = FalsePositiveEngine()
        finding = {'type': 'generic_pp'}
        
        result = engine.secondary_verify(finding, driver=None)
        
        assert result.status == VerificationStatus.UNCERTAIN
    
    def test_caching(self):
        """Results should be cached."""
        engine = FalsePositiveEngine()
        finding = {'type': 'test', 'url': 'http://test.com', 'payload': 'test'}
        
        result1 = engine.secondary_verify(finding)
        result2 = engine.secondary_verify(finding)
        
        assert result1 is result2  # Same cached object


class TestCalculateConfidence:
    """Tests for calculate_confidence method."""
    
    def test_cve_boosts_score(self):
        """CVE should boost confidence."""
        engine = FalsePositiveEngine()
        finding = {'cve': 'CVE-2019-11358'}
        
        score = engine.calculate_confidence(finding)
        assert score >= 0.7
    
    def test_verified_boosts_score(self):
        """Browser verification should boost confidence."""
        engine = FalsePositiveEngine()
        finding = {'verified': True}
        
        score = engine.calculate_confidence(finding)
        assert score >= 0.7
    
    def test_critical_severity_boosts(self):
        """CRITICAL severity should boost slightly."""
        engine = FalsePositiveEngine()
        finding_critical = {'severity': 'CRITICAL'}
        finding_low = {'severity': 'LOW'}
        
        score_critical = engine.calculate_confidence(finding_critical)
        score_low = engine.calculate_confidence(finding_low)
        
        assert score_critical > score_low
    
    def test_reflection_penalty(self):
        """Reflected-only should reduce confidence."""
        engine = FalsePositiveEngine()
        finding = {}
        evidence = {'reflected_only': True}
        
        score = engine.calculate_confidence(finding, evidence)
        assert score < 0.5
    
    def test_score_clamped(self):
        """Score should be between 0 and 1."""
        engine = FalsePositiveEngine()
        
        # Maximum boost
        finding_max = {'cve': 'X', 'verified': True, 'type': 'persistent', 'severity': 'CRITICAL'}
        score_max = engine.calculate_confidence(finding_max)
        assert 0.0 <= score_max <= 1.0
        
        # Maximum penalty
        finding_min = {}
        evidence_min = {'reflected_only': True, 'response_only': True}
        score_min = engine.calculate_confidence(finding_min, evidence_min)
        assert 0.0 <= score_min <= 1.0


class TestFilterFindings:
    """Tests for filter_findings method."""
    
    def test_filters_low_confidence(self):
        """Low confidence findings should be filtered."""
        engine = FalsePositiveEngine()
        findings = [
            {'type': 'generic', 'severity': 'LOW'},
            {'cve': 'CVE-2019-11358', 'severity': 'CRITICAL'}
        ]
        
        confirmed, filtered = engine.filter_findings(findings, min_confidence=0.6)
        
        # CVE finding should pass, generic might be filtered
        assert len(confirmed) >= 1
        cve_found = any(f.get('cve') for f in confirmed)
        assert cve_found
    
    def test_adds_verification_info(self):
        """Should add fp_verification to findings."""
        engine = FalsePositiveEngine()
        findings = [{'type': 'test'}]
        
        confirmed, filtered = engine.filter_findings(findings)
        all_findings = confirmed + filtered
        
        assert all('fp_verification' in f for f in all_findings)
        assert all('confidence_score' in f for f in all_findings)
    
    def test_empty_findings(self):
        """Empty findings list should work."""
        engine = FalsePositiveEngine()
        
        confirmed, filtered = engine.filter_findings([])
        
        assert confirmed == []
        assert filtered == []


class TestValidateJqueryDetection:
    """Tests for validate_jquery_detection method."""
    
    def test_version_in_source(self):
        """Version in source should be confirmed."""
        engine = FalsePositiveEngine()
        response = '<script src="jquery-3.4.1.min.js"></script>'
        
        result = engine.validate_jquery_detection('3.4.1', response)
        
        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence >= 0.8
    
    def test_version_not_in_source(self):
        """Version not in source should be uncertain."""
        engine = FalsePositiveEngine()
        response = '<script src="jquery.min.js"></script>'
        
        result = engine.validate_jquery_detection('3.4.1', response)
        
        assert result.status == VerificationStatus.UNCERTAIN
    
    def test_no_version(self):
        """No version should be skipped."""
        engine = FalsePositiveEngine()
        
        result = engine.validate_jquery_detection('', '<html></html>')
        
        assert result.status == VerificationStatus.SKIPPED


class TestGetFPEngine:
    """Tests for singleton getter."""
    
    def test_returns_instance(self):
        """Should return FalsePositiveEngine instance."""
        engine = get_fp_engine()
        assert isinstance(engine, FalsePositiveEngine)
    
    def test_singleton(self):
        """Should return same instance."""
        engine1 = get_fp_engine()
        engine2 = get_fp_engine()
        assert engine1 is engine2
