"""
Mobile App Testing Module for PPMAP v5.0
Scan React Native, Capacitor, and Ionic apps for prototype pollution.
"""
import os
import re
import json
import zipfile
import tempfile
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

# Import SAST scanner for JS analysis
try:
    from ppmap.sast import SASTScanner, scan_js
except ImportError:
    SASTScanner = None
    scan_js = None

logger = logging.getLogger(__name__)


@dataclass
class MobileFinding:
    """Mobile app vulnerability finding."""
    app_path: str
    file_path: str
    finding_type: str
    description: str
    severity: str = "MEDIUM"
    framework: str = "unknown"
    line_number: int = 0
    code_snippet: str = ""
    recommendation: str = ""


@dataclass
class MobileAppInfo:
    """Mobile app metadata."""
    path: str
    platform: str  # 'android' or 'ios'
    framework: str  # 'react-native', 'capacitor', 'ionic', 'cordova', 'native'
    package_name: str = ""
    version: str = ""
    js_bundles: List[str] = field(default_factory=list)
    webview_urls: List[str] = field(default_factory=list)


class MobileAppScanner:
    """
    Scanner for mobile application prototype pollution.
    
    Supports:
    - Android APK analysis
    - iOS IPA analysis (limited without macOS)
    - React Native bundle extraction
    - Capacitor/Ionic detection
    - Cordova plugin analysis
    - WebView configuration scanning
    """
    
    # React Native bundle patterns
    RN_BUNDLE_PATTERNS = [
        'index.android.bundle',
        'index.ios.bundle',
        'main.jsbundle',
        'index.bundle',
        'assets/index.android.bundle',
    ]
    
    # Capacitor/Ionic patterns
    CAPACITOR_PATTERNS = [
        'capacitor.config.json',
        'capacitor.config.ts',
        'public/index.html',
    ]
    
    IONIC_PATTERNS = [
        'ionic.config.json',
        'www/index.html',
        'www/build/main.js',
    ]
    
    # Cordova patterns
    CORDOVA_PATTERNS = [
        'config.xml',
        'www/cordova.js',
        'www/cordova_plugins.js',
    ]
    
    # Dangerous patterns in mobile JS
    MOBILE_DANGEROUS_PATTERNS = {
        'eval_usage': {
            'pattern': r'\beval\s*\(',
            'severity': 'HIGH',
            'description': 'Dynamic code execution via eval()'
        },
        'function_constructor': {
            'pattern': r'new\s+Function\s*\(',
            'severity': 'HIGH', 
            'description': 'Dynamic function creation'
        },
        'webview_js_interface': {
            'pattern': r'addJavascriptInterface|evaluateJavascript',
            'severity': 'MEDIUM',
            'description': 'WebView JavaScript bridge detected'
        },
        'deep_link_handler': {
            'pattern': r'Linking\.addEventListener|handleOpenURL',
            'severity': 'MEDIUM',
            'description': 'Deep link handler may process untrusted data'
        },
        'async_storage': {
            'pattern': r'AsyncStorage\.(getItem|setItem|mergeItem)',
            'severity': 'LOW',
            'description': 'AsyncStorage usage - check for PP in stored data'
        },
        'fetch_no_validate': {
            'pattern': r'fetch\s*\([^)]+\)\.then\([^)]*JSON\.parse',
            'severity': 'MEDIUM',
            'description': 'Fetch without response validation'
        },
        'postmessage': {
            'pattern': r'postMessage|onmessage',
            'severity': 'MEDIUM',
            'description': 'postMessage communication detected'
        },
        'lodash_merge': {
            'pattern': r'_\.merge|lodash\.merge|deepmerge',
            'severity': 'HIGH',
            'description': 'Deep merge function - PP risk'
        },
        'object_assign_spread': {
            'pattern': r'Object\.assign\([^,]+,\s*\w+\)|\.\.\.props|\.\.\.data',
            'severity': 'MEDIUM',
            'description': 'Object spread/assign with external data'
        },
    }
    
    def __init__(self, 
                 temp_dir: Optional[str] = None,
                 use_sast: bool = True,
                 max_workers: int = 4):
        """
        Initialize mobile scanner.
        
        Args:
            temp_dir: Directory for extracting app contents
            use_sast: Use SAST scanner for JS analysis
            max_workers: Parallel analysis threads
        """
        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix='ppmap_mobile_')
        self.use_sast = use_sast and SASTScanner is not None
        self.max_workers = max_workers
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        for name, info in self.MOBILE_DANGEROUS_PATTERNS.items():
            try:
                self._compiled_patterns[name] = re.compile(info['pattern'], re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid pattern {name}: {e}")
    
    def detect_framework(self, extracted_path: str) -> str:
        """Detect mobile framework from extracted contents."""
        # Check React Native
        for pattern in self.RN_BUNDLE_PATTERNS:
            if os.path.exists(os.path.join(extracted_path, pattern)):
                return 'react-native'
        
        # Check Capacitor
        for pattern in self.CAPACITOR_PATTERNS:
            if os.path.exists(os.path.join(extracted_path, pattern)):
                return 'capacitor'
        
        # Check Ionic
        for pattern in self.IONIC_PATTERNS:
            if os.path.exists(os.path.join(extracted_path, pattern)):
                return 'ionic'
        
        # Check Cordova
        for pattern in self.CORDOVA_PATTERNS:
            if os.path.exists(os.path.join(extracted_path, pattern)):
                return 'cordova'
        
        return 'native'
    
    def extract_apk(self, apk_path: str) -> Tuple[str, MobileAppInfo]:
        """
        Extract Android APK contents.
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Tuple of (extracted_path, app_info)
        """
        extract_path = os.path.join(self.temp_dir, Path(apk_path).stem)
        os.makedirs(extract_path, exist_ok=True)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                apk.extractall(extract_path)
        except zipfile.BadZipFile:
            logger.error(f"Invalid APK file: {apk_path}")
            raise ValueError(f"Invalid APK: {apk_path}")
        
        framework = self.detect_framework(extract_path)
        js_bundles = self._find_js_bundles(extract_path)
        
        # Parse package info from AndroidManifest (simplified)
        package_name = self._extract_package_name(extract_path)
        
        app_info = MobileAppInfo(
            path=apk_path,
            platform='android',
            framework=framework,
            package_name=package_name,
            js_bundles=js_bundles
        )
        
        return extract_path, app_info
    
    def extract_ipa(self, ipa_path: str) -> Tuple[str, MobileAppInfo]:
        """
        Extract iOS IPA contents.
        
        Args:
            ipa_path: Path to IPA file
            
        Returns:
            Tuple of (extracted_path, app_info)
        """
        extract_path = os.path.join(self.temp_dir, Path(ipa_path).stem)
        os.makedirs(extract_path, exist_ok=True)
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa:
                ipa.extractall(extract_path)
        except zipfile.BadZipFile:
            logger.error(f"Invalid IPA file: {ipa_path}")
            raise ValueError(f"Invalid IPA: {ipa_path}")
        
        # Find Payload/*.app directory
        payload_dir = os.path.join(extract_path, 'Payload')
        app_dir = extract_path
        if os.path.exists(payload_dir):
            apps = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
            if apps:
                app_dir = os.path.join(payload_dir, apps[0])
        
        framework = self.detect_framework(app_dir)
        js_bundles = self._find_js_bundles(app_dir)
        
        app_info = MobileAppInfo(
            path=ipa_path,
            platform='ios',
            framework=framework,
            js_bundles=js_bundles
        )
        
        return app_dir, app_info
    
    def _find_js_bundles(self, path: str) -> List[str]:
        """Find JavaScript bundles in extracted app."""
        bundles = []
        
        for root, dirs, files in os.walk(path):
            # Skip common non-JS directories
            dirs[:] = [d for d in dirs if d not in ['lib', 'res', 'META-INF']]
            
            for f in files:
                if f.endswith(('.js', '.bundle', '.jsbundle')):
                    bundles.append(os.path.join(root, f))
        
        return bundles
    
    def _extract_package_name(self, extract_path: str) -> str:
        """Extract package name from AndroidManifest.xml."""
        manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            return 'unknown'
        
        try:
            # Try using aapt if available
            result = subprocess.run(
                ['aapt', 'dump', 'badging', extract_path],
                capture_output=True, text=True, timeout=10
            )
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return 'unknown'
    
    def scan_js_bundle(self, bundle_path: str, framework: str) -> List[MobileFinding]:
        """
        Scan a JavaScript bundle for PP vulnerabilities.
        
        Args:
            bundle_path: Path to JS bundle
            framework: Detected framework
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            with open(bundle_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"Could not read {bundle_path}: {e}")
            return findings
        
        lines = content.split('\n')
        
        # Check mobile-specific patterns
        for name, pattern in self._compiled_patterns.items():
            info = self.MOBILE_DANGEROUS_PATTERNS[name]
            
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    findings.append(MobileFinding(
                        app_path='',
                        file_path=bundle_path,
                        finding_type=name,
                        description=info['description'],
                        severity=info['severity'],
                        framework=framework,
                        line_number=line_num,
                        code_snippet=line.strip()[:200]
                    ))
        
        # Use SAST scanner for additional checks
        if self.use_sast and scan_js:
            sast_findings = scan_js(bundle_path, include_low_severity=True)
            for sast in sast_findings:
                findings.append(MobileFinding(
                    app_path='',
                    file_path=bundle_path,
                    finding_type=f"sast_{sast.get('sink', 'unknown')}",
                    description=f"SAST: {sast.get('sink', '')}",
                    severity=sast.get('severity', 'MEDIUM'),
                    framework=framework,
                    line_number=sast.get('line', 0),
                    code_snippet=sast.get('snippet', ''),
                    recommendation=sast.get('recommendation', '')
                ))
        
        return findings
    
    def check_webview_config(self, extract_path: str) -> List[MobileFinding]:
        """Check WebView configuration for security issues."""
        findings = []
        
        # Check Android WebView settings
        java_files = []
        for root, dirs, files in os.walk(extract_path):
            for f in files:
                if f.endswith('.smali'):  # Decompiled code
                    java_files.append(os.path.join(root, f))
        
        webview_patterns = {
            'setJavaScriptEnabled': 'WebView JavaScript enabled',
            'setAllowFileAccess': 'WebView file access enabled',
            'setAllowUniversalAccessFromFileURLs': 'Universal file access enabled',
            'addJavascriptInterface': 'JavaScript interface exposed',
        }
        
        for filepath in java_files[:100]:  # Limit for performance
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    for pattern, desc in webview_patterns.items():
                        if pattern in content:
                            findings.append(MobileFinding(
                                app_path='',
                                file_path=filepath,
                                finding_type='webview_config',
                                description=desc,
                                severity='MEDIUM',
                                framework='native'
                            ))
            except Exception:
                pass
        
        return findings
    
    def scan_app(self, app_path: str) -> Dict:
        """
        Scan mobile app for prototype pollution vulnerabilities.
        
        Args:
            app_path: Path to APK or IPA file
            
        Returns:
            Scan results dict
        """
        results = {
            'app_path': app_path,
            'platform': None,
            'framework': None,
            'package_name': None,
            'findings': [],
            'js_bundles_scanned': 0,
            'stats': {}
        }
        
        # Determine platform and extract
        if app_path.lower().endswith('.apk'):
            extract_path, app_info = self.extract_apk(app_path)
        elif app_path.lower().endswith('.ipa'):
            extract_path, app_info = self.extract_ipa(app_path)
        else:
            raise ValueError(f"Unsupported file type: {app_path}")
        
        results['platform'] = app_info.platform
        results['framework'] = app_info.framework
        results['package_name'] = app_info.package_name
        
        logger.info(f"Scanning {app_info.framework} app: {app_path}")
        logger.info(f"Found {len(app_info.js_bundles)} JS bundles")
        
        all_findings = []
        
        # Scan JS bundles in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.scan_js_bundle, bundle, app_info.framework): bundle
                for bundle in app_info.js_bundles
            }
            
            for future in futures:
                try:
                    bundle_findings = future.result()
                    for f in bundle_findings:
                        f.app_path = app_path
                    all_findings.extend(bundle_findings)
                except Exception as e:
                    logger.debug(f"Bundle scan error: {e}")
        
        results['js_bundles_scanned'] = len(app_info.js_bundles)
        
        # Check WebView configuration
        webview_findings = self.check_webview_config(extract_path)
        for f in webview_findings:
            f.app_path = app_path
        all_findings.extend(webview_findings)
        
        results['findings'] = [
            {
                'file': f.file_path,
                'type': f.finding_type,
                'description': f.description,
                'severity': f.severity,
                'framework': f.framework,
                'line': f.line_number,
                'snippet': f.code_snippet,
                'recommendation': f.recommendation
            }
            for f in all_findings
        ]
        
        # Stats
        by_severity = {}
        for f in all_findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        results['stats'] = {
            'total_findings': len(all_findings),
            'by_severity': by_severity,
            'js_bundles': len(app_info.js_bundles)
        }
        
        return results
    
    def cleanup(self):
        """Remove temporary extracted files."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


def scan_mobile_app(app_path: str, **kwargs) -> Dict:
    """
    Convenience function to scan mobile app.
    
    Args:
        app_path: Path to APK or IPA
        **kwargs: Additional options
        
    Returns:
        Scan results
    """
    scanner = MobileAppScanner(**kwargs)
    try:
        return scanner.scan_app(app_path)
    finally:
        scanner.cleanup()


# Frida integration for runtime analysis (optional)
class FridaIntegration:
    """
    Frida-based runtime analysis for mobile apps.
    Requires frida-tools installed.
    """
    
    HOOK_SCRIPT = """
    // PP Detection Hooks
    
    // Hook Object.prototype modifications
    var originalDefineProperty = Object.defineProperty;
    Object.defineProperty = function(obj, prop, descriptor) {
        if (obj === Object.prototype || obj === Array.prototype) {
            send({
                type: 'prototype_modification',
                property: prop,
                stack: new Error().stack
            });
        }
        return originalDefineProperty.apply(this, arguments);
    };
    
    // Hook dangerous functions
    ['merge', 'extend', 'assign', 'defaults', 'defaultsDeep'].forEach(function(fn) {
        if (typeof _[fn] === 'function') {
            var original = _[fn];
            _[fn] = function() {
                send({
                    type: 'dangerous_call',
                    function: fn,
                    args: JSON.stringify(Array.from(arguments).slice(0, 2))
                });
                return original.apply(this, arguments);
            };
        }
    });
    """
    
    def __init__(self, package_name: str, device_id: Optional[str] = None):
        """
        Initialize Frida integration.
        
        Args:
            package_name: Target application package name
            device_id: Optional device ID for USB connection
        """
        self.package_name = package_name
        self.device_id = device_id
        self.session = None
        self.script = None
        self.findings = []
    
    def connect(self) -> bool:
        """Connect to device and attach to app."""
        try:
            import frida
            
            if self.device_id:
                device = frida.get_device(self.device_id)
            else:
                device = frida.get_usb_device()
            
            self.session = device.attach(self.package_name)
            return True
        except ImportError:
            logger.error("Frida not installed. Install with: pip install frida-tools")
            return False
        except Exception as e:
            logger.error(f"Frida connection failed: {e}")
            return False
    
    def start_monitoring(self):
        """Start PP monitoring with Frida hooks."""
        if not self.session:
            raise RuntimeError("Not connected. Call connect() first.")
        
        self.script = self.session.create_script(self.HOOK_SCRIPT)
        self.script.on('message', self._on_message)
        self.script.load()
    
    def _on_message(self, message, data):
        """Handle Frida messages."""
        if message['type'] == 'send':
            payload = message['payload']
            self.findings.append(payload)
            logger.info(f"[Frida] {payload.get('type')}: {payload}")
    
    def stop(self):
        """Stop monitoring and detach."""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
    
    def get_findings(self) -> List[Dict]:
        """Get collected runtime findings."""
        return self.findings
