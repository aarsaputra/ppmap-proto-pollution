"""
Unit tests for SAST Scanner
"""
import pytest
import tempfile
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.sast import (
    SASTScanner,
    SASTFinding,
    DANGEROUS_SINKS,
    scan_js
)


class TestSASTScanner:
    """Tests for SASTScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return SASTScanner(max_workers=2, include_low_severity=True)
    
    @pytest.fixture
    def temp_js_file(self):
        """Create temporary JS file with vulnerable code."""
        content = '''
// Vulnerable code examples
const obj = {};
$.extend(obj, userInput);

const merged = _.merge({}, data, untrusted);

Object.assign(target, req.body);

const value = obj[userKey] = userValue;
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(content)
            return f.name
    
    @pytest.fixture
    def temp_safe_file(self):
        """Create temporary safe JS file."""
        content = '''
// Safe code
const x = 1 + 2;
console.log("Hello world");
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(content)
            return f.name
    
    def test_init(self, scanner):
        """Should initialize with settings."""
        assert scanner.max_workers == 2
        assert scanner.include_low_severity is True
    
    def test_patterns_compiled(self, scanner):
        """Should compile regex patterns."""
        assert len(scanner._compiled_patterns) > 0
    
    def test_scan_file_finds_jquery_extend(self, scanner, temp_js_file):
        """Should find $.extend usage."""
        findings = scanner.scan_file(temp_js_file)
        
        sink_types = [f.sink_type for f in findings]
        assert '$.extend' in sink_types
        
        # Cleanup
        os.unlink(temp_js_file)
    
    def test_scan_file_finds_lodash_merge(self, scanner, temp_js_file):
        """Should find _.merge usage."""
        findings = scanner.scan_file(temp_js_file)
        
        sink_types = [f.sink_type for f in findings]
        assert '_.merge' in sink_types
        
        os.unlink(temp_js_file)
    
    def test_scan_file_finds_object_assign(self, scanner, temp_js_file):
        """Should find Object.assign usage."""
        findings = scanner.scan_file(temp_js_file)
        
        sink_types = [f.sink_type for f in findings]
        assert 'Object.assign' in sink_types
        
        os.unlink(temp_js_file)
    
    def test_scan_safe_file(self, scanner, temp_safe_file):
        """Should not find vulnerabilities in safe code."""
        findings = scanner.scan_file(temp_safe_file)
        
        # Should have no or very few findings
        assert len(findings) == 0
        
        os.unlink(temp_safe_file)
    
    def test_skip_minified(self, scanner):
        """Should skip minified files."""
        content = 'a' * 1000  # Long single line
        with tempfile.NamedTemporaryFile(mode='w', suffix='.min.js', delete=False) as f:
            f.write(content)
            filepath = f.name
        
        findings = scanner.scan_file(filepath)
        assert len(findings) == 0
        
        os.unlink(filepath)
    
    def test_scan_directory(self, scanner):
        """Should scan directory recursively."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            js_file = os.path.join(tmpdir, 'test.js')
            with open(js_file, 'w') as f:
                f.write('$.extend({}, data);')
            
            findings = scanner.scan_directory(tmpdir)
            
            assert len(findings) > 0
    
    def test_generate_report(self, scanner, temp_js_file):
        """Should generate summary report."""
        findings = scanner.scan_file(temp_js_file)
        report = scanner.generate_report(findings)
        
        assert 'total_findings' in report
        assert 'by_severity' in report
        assert 'by_sink_type' in report
        assert report['total_findings'] == len(findings)
        
        os.unlink(temp_js_file)


class TestSASTFinding:
    """Tests for SASTFinding dataclass."""
    
    def test_create_finding(self):
        """Should create finding with defaults."""
        finding = SASTFinding(
            filepath='/path/to/file.js',
            line_number=10,
            sink_type='$.extend',
            code_snippet='$.extend({}, data)'
        )
        
        assert finding.severity == 'MEDIUM'
        assert finding.confidence == 'medium'


class TestDangerousSinks:
    """Tests for sink definitions."""
    
    def test_sinks_have_pattern(self):
        """All sinks should have regex pattern."""
        for sink_name, sink_info in DANGEROUS_SINKS.items():
            assert 'pattern' in sink_info
            assert 'severity' in sink_info
    
    def test_jquery_extend_pattern(self):
        """jQuery extend pattern should match."""
        import re
        pattern = DANGEROUS_SINKS['$.extend']['pattern']
        
        test_cases = [
            '$.extend(',
            '$.extend(true,',
            '$.extend( obj,',
        ]
        
        for test in test_cases:
            assert re.search(pattern, test, re.IGNORECASE)


class TestScanJS:
    """Tests for scan_js convenience function."""
    
    def test_scan_file(self):
        """Should scan single file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('$.extend({}, data);')
            filepath = f.name
        
        results = scan_js(filepath)
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        os.unlink(filepath)
    
    def test_scan_returns_dicts(self):
        """Should return list of dicts."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('_.merge({}, input);')
            filepath = f.name
        
        results = scan_js(filepath, include_low_severity=True)
        
        for result in results:
            assert isinstance(result, dict)
            assert 'type' in result
            assert result['type'] == 'sast_pp_sink'
        
        os.unlink(filepath)
