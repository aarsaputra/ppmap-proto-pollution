"""
Unit tests for Mobile App Scanner
"""
import pytest
import tempfile
import zipfile
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.mobile import (
    MobileAppScanner,
    MobileFinding,
    MobileAppInfo,
    scan_mobile_app
)


class TestMobileAppScanner:
    """Tests for MobileAppScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return MobileAppScanner(max_workers=2)
    
    @pytest.fixture
    def mock_apk(self, tmp_path):
        """Create a mock APK file."""
        apk_path = tmp_path / "test.apk"
        
        with zipfile.ZipFile(apk_path, 'w') as apk:
            # Add a fake React Native bundle
            bundle_content = """
            // Test React Native bundle
            import { merge } from 'lodash';
            _.merge(state, action.payload);
            eval(userInput);
            AsyncStorage.getItem('user');
            """
            apk.writestr('assets/index.android.bundle', bundle_content)
            
            # Add manifest placeholder
            apk.writestr('AndroidManifest.xml', '<manifest/>')
        
        return str(apk_path)
    
    @pytest.fixture
    def mock_ipa(self, tmp_path):
        """Create a mock IPA file."""
        ipa_path = tmp_path / "test.ipa"
        
        with zipfile.ZipFile(ipa_path, 'w') as ipa:
            # Add a fake Capacitor structure
            ipa.writestr('Payload/App.app/public/index.html', '<html></html>')
            ipa.writestr('Payload/App.app/capacitor.config.json', '{}')
            ipa.writestr('Payload/App.app/public/main.js', 'Object.assign(a, b);')
        
        return str(ipa_path)
    
    def test_init(self, scanner):
        """Should initialize with default settings."""
        assert scanner.max_workers == 2
        assert len(scanner._compiled_patterns) > 0
    
    def test_detect_framework_react_native(self, scanner, tmp_path):
        """Should detect React Native framework."""
        (tmp_path / 'assets').mkdir()
        (tmp_path / 'assets' / 'index.android.bundle').touch()
        
        framework = scanner.detect_framework(str(tmp_path))
        
        assert framework == 'react-native'
    
    def test_detect_framework_capacitor(self, scanner, tmp_path):
        """Should detect Capacitor framework."""
        (tmp_path / 'capacitor.config.json').touch()
        
        framework = scanner.detect_framework(str(tmp_path))
        
        assert framework == 'capacitor'
    
    def test_detect_framework_ionic(self, scanner, tmp_path):
        """Should detect Ionic framework."""
        (tmp_path / 'ionic.config.json').touch()
        
        framework = scanner.detect_framework(str(tmp_path))
        
        assert framework == 'ionic'
    
    def test_detect_framework_cordova(self, scanner, tmp_path):
        """Should detect Cordova framework."""
        (tmp_path / 'www').mkdir()
        (tmp_path / 'www' / 'cordova.js').touch()
        
        framework = scanner.detect_framework(str(tmp_path))
        
        assert framework == 'cordova'
    
    def test_detect_framework_native(self, scanner, tmp_path):
        """Should default to native for unknown framework."""
        framework = scanner.detect_framework(str(tmp_path))
        
        assert framework == 'native'
    
    def test_extract_apk(self, scanner, mock_apk):
        """Should extract APK contents."""
        extract_path, app_info = scanner.extract_apk(mock_apk)
        
        assert os.path.exists(extract_path)
        assert app_info.platform == 'android'
        assert app_info.framework == 'react-native'
        assert len(app_info.js_bundles) > 0
        
        scanner.cleanup()
    
    def test_extract_ipa(self, scanner, mock_ipa):
        """Should extract IPA contents."""
        extract_path, app_info = scanner.extract_ipa(mock_ipa)
        
        assert os.path.exists(extract_path)
        assert app_info.platform == 'ios'
        assert app_info.framework == 'capacitor'
        
        scanner.cleanup()
    
    def test_scan_js_bundle(self, scanner, tmp_path):
        """Should find dangerous patterns in JS bundle."""
        bundle = tmp_path / "test.js"
        bundle.write_text("""
            eval(userInput);
            _.merge({}, untrusted);
            AsyncStorage.getItem('key');
        """)
        
        findings = scanner.scan_js_bundle(str(bundle), 'react-native')
        
        assert len(findings) >= 2  # eval and lodash_merge
        
        types = [f.finding_type for f in findings]
        assert 'eval_usage' in types
        assert 'lodash_merge' in types
    
    def test_scan_app_apk(self, scanner, mock_apk):
        """Should scan entire APK app."""
        results = scanner.scan_app(mock_apk)
        
        assert results['platform'] == 'android'
        assert results['framework'] == 'react-native'
        assert results['js_bundles_scanned'] >= 1
        assert 'findings' in results
        assert 'stats' in results
        
        scanner.cleanup()
    
    def test_scan_app_invalid_file(self, scanner, tmp_path):
        """Should raise error for invalid file type."""
        invalid = tmp_path / "test.txt"
        invalid.write_text("not an app")
        
        with pytest.raises(ValueError, match="Unsupported file type"):
            scanner.scan_app(str(invalid))


class TestMobileFinding:
    """Tests for MobileFinding dataclass."""
    
    def test_create_finding(self):
        """Should create finding with defaults."""
        finding = MobileFinding(
            app_path='/path/to/app.apk',
            file_path='/path/to/bundle.js',
            finding_type='eval_usage',
            description='eval() detected'
        )
        
        assert finding.severity == 'MEDIUM'
        assert finding.framework == 'unknown'


class TestMobileAppInfo:
    """Tests for MobileAppInfo dataclass."""
    
    def test_create_info(self):
        """Should create app info."""
        info = MobileAppInfo(
            path='/path/to/app.apk',
            platform='android',
            framework='react-native'
        )
        
        assert info.package_name == ''
        assert info.js_bundles == []


class TestScanMobileApp:
    """Tests for scan_mobile_app convenience function."""
    
    def test_scan_returns_dict(self, tmp_path):
        """Should return dict with results."""
        apk_path = tmp_path / "test.apk"
        
        with zipfile.ZipFile(apk_path, 'w') as apk:
            apk.writestr('test.js', 'console.log("test");')
        
        results = scan_mobile_app(str(apk_path))
        
        assert isinstance(results, dict)
        assert 'platform' in results
        assert 'findings' in results


class TestDangerousPatterns:
    """Tests for dangerous pattern detection."""
    
    @pytest.fixture
    def scanner(self):
        return MobileAppScanner()
    
    def test_eval_detection(self, scanner, tmp_path):
        """Should detect eval usage."""
        js = tmp_path / "test.js"
        js.write_text("eval(untrusted);")
        
        findings = scanner.scan_js_bundle(str(js), 'unknown')
        
        assert any(f.finding_type == 'eval_usage' for f in findings)
    
    def test_function_constructor(self, scanner, tmp_path):
        """Should detect Function constructor."""
        js = tmp_path / "test.js"
        js.write_text("new Function('a', 'return a')();")
        
        findings = scanner.scan_js_bundle(str(js), 'unknown')
        
        assert any(f.finding_type == 'function_constructor' for f in findings)
    
    def test_postmessage(self, scanner, tmp_path):
        """Should detect postMessage usage."""
        js = tmp_path / "test.js"
        js.write_text("window.postMessage(data, '*');")
        
        findings = scanner.scan_js_bundle(str(js), 'unknown')
        
        assert any(f.finding_type == 'postmessage' for f in findings)
