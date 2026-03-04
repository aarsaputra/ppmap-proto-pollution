#!/usr/bin/env python3
"""
PPMAP Local Security Scanning Script
Run comprehensive security checks locally before committing

Usage:
    python scripts/security_scan.py [--full] [--fix]
    
Options:
    --full          Run comprehensive scan (slower, includes dependency checks)
    --fix           Auto-fix issues where possible
    --verbose       Verbose output
"""

import subprocess
import sys
import os
from pathlib import Path
import json
import time
from typing import List, Tuple
import argparse

class SecurityScanner:
    """Local security scanning orchestrator"""
    
    def __init__(self, full: bool = False, fix: bool = False, verbose: bool = False):
        self.full = full
        self.fix = fix
        self.verbose = verbose
        self.results = {}
        self.errors = []
        self.root_dir = Path(__file__).parent.parent
        
    def run_scan(self, tool: str, command: List[str]) -> Tuple[bool, str]:
        """Run security tool and capture output"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=self.root_dir,
                timeout=60
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if self.verbose:
                print(f"[*] {tool} output:\n{output}")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            return False, f"Timeout running {tool}"
        except Exception as e:
            return False, str(e)
    
    def check_dependencies(self) -> bool:
        """Check for vulnerable dependencies"""
        print("\n🔍 Checking dependencies for vulnerabilities...")
        
        # Safety check
        print("  → Running safety check...")
        success, output = self.run_scan(
            "safety",
            ["safety", "check", "--json"]
        )
        
        if not success:
            self.errors.append(f"Safety check failed: {output[:200]}")
        else:
            try:
                data = json.loads(output)
                vulnerability_count = len(data)
                if vulnerability_count > 0:
                    print(f"  ⚠️  Found {vulnerability_count} vulnerabilities")
                    self.results['dependencies'] = 'FAILED'
                else:
                    print(f"  ✅ No known vulnerabilities found")
                    self.results['dependencies'] = 'PASSED'
            except:
                self.results['dependencies'] = 'UNKNOWN'
        
        return success
    
    def check_bandit(self) -> bool:
        """Run Bandit security linter"""
        print("\n🔍 Running Bandit security scan...")
        
        command = [
            "bandit",
            "-r", "ppmap/",
            "-f", "json",
            "-o", "/tmp/bandit-report.json"
        ]
        
        if self.fix:
            command.append("--exit-zero")
        
        success, output = self.run_scan("bandit", command)
        
        try:
            with open("/tmp/bandit-report.json") as f:
                report = json.load(f)
                
            issues = len(report.get("results", []))
            
            if issues > 0:
                print(f"  ⚠️  Found {issues} potential security issues")
                for issue in report.get("results", [])[:3]:
                    print(f"      - {issue['test_id']}: {issue['issue_text'][:60]}")
                self.results['bandit'] = 'FAILED'
            else:
                print(f"  ✅ No security issues found")
                self.results['bandit'] = 'PASSED'
                
        except:
            self.results['bandit'] = 'UNKNOWN'
        
        return not (issues > 0)
    
    def check_custom_security(self) -> bool:
        """Run PPMAP-specific security tests"""
        print("\n🔍 Running PPMAP custom security tests...")
        
        # Add repo to path to ensure imports work
        import sys
        sys.path.insert(0, str(self.root_dir))
        
        # Test ReDoS protection
        print("  → Testing ReDoS protection...")
        try:
            import re
            import time
            from ppmap.sast import DANGEROUS_SINKS
            
            all_safe = True
            for sink_name in ['bracket_notation', 'JSON.parse']:
                if sink_name not in DANGEROUS_SINKS:
                    continue
                
                pattern = DANGEROUS_SINKS[sink_name]['pattern']
                regex = re.compile(pattern)
                
                malicious = 'x[' + '['*100 + '] = 1;'
                start = time.time()
                try:
                    regex.search(malicious)
                except:
                    pass
                elapsed = time.time() - start
                
                if elapsed > 0.1:
                    print(f"    ⚠️  {sink_name} slow: {elapsed:.4f}s")
                    all_safe = False
                else:
                    print(f"    ✅ {sink_name}: {elapsed:.4f}s")
            
            self.results['redos'] = 'PASSED' if all_safe else 'FAILED'
            
        except Exception as e:
            print(f"    ❌ Error: {e}")
            self.results['redos'] = 'FAILED'
        
        # Test path traversal protection
        print("  → Testing path traversal protection...")
        try:
            import tempfile
            from ppmap.mobile import MobileAppScanner
            
            with tempfile.TemporaryDirectory() as tmpdir:
                scanner = MobileAppScanner(temp_dir=tmpdir)
                
                try:
                    scanner._validate_safe_path(tmpdir, '../../etc/passwd')
                    print(f"    ❌ Path traversal NOT blocked!")
                    self.results['path_traversal'] = 'FAILED'
                except ValueError:
                    print(f"    ✅ Path traversal blocked")
                    self.results['path_traversal'] = 'PASSED'
                    
        except Exception as e:
            print(f"    ❌ Error: {e}")
            self.results['path_traversal'] = 'FAILED'
        
        # Test SSL configuration
        print("  → Testing SSL verification config...")
        try:
            from ppmap.engine import AsyncScanner
            
            scanner = AsyncScanner()
            if scanner.verify_ssl == True:
                print(f"    ✅ Default: SSL verification enabled")
                self.results['ssl_config'] = 'PASSED'
            else:
                print(f"    ❌ Default: SSL verification disabled")
                self.results['ssl_config'] = 'FAILED'
                
        except Exception as e:
            print(f"    ❌ Error: {e}")
            self.results['ssl_config'] = 'FAILED'
        
        return 'FAILED' not in self.results.values()
    
    def check_secrets(self) -> bool:
        """Detect hardcoded secrets"""
        print("\n🔍 Checking for hardcoded secrets...")
        
        secret_patterns = {
            'api_keys': r'["\']api[_-]?key["\']?\s*[=:]\s*["\'][a-zA-Z0-9]{20,}',
            'passwords': r'["\']password["\']?\s*[=:]\s*["\'][^"\']{8,}',
            'tokens': r'["\']api[_-]?token["\']?\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}',
            'aws_keys': r'AKIA[0-9A-Z]{16}',
            'private_keys': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY',
        }
        
        found_secrets = []
        
        for root, dirs, files in os.walk(self.root_dir / 'ppmap'):
            # Skip cache/build dirs
            dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git']]
            
            for file in files:
                if not file.endswith('.py'):
                    continue
                
                filepath = Path(root) / file
                try:
                    content = filepath.read_text()
                    for pattern_name, pattern in secret_patterns.items():
                        import re
                        if re.search(pattern, content):
                            found_secrets.append(f"{filepath}: {pattern_name}")
                except:
                    pass
        
        if found_secrets:
            print(f"  ⚠️  Found {len(found_secrets)} potential secrets:")
            for secret in found_secrets[:5]:
                print(f"      - {secret}")
            self.results['secrets'] = 'FAILED'
            return False
        else:
            print(f"  ✅ No hardcoded secrets detected")
            self.results['secrets'] = 'PASSED'
            return True
    
    def check_tests(self) -> bool:
        """Run security test suite"""
        print("\n🔍 Running security test suite...")
        
        command = [
            "pytest",
            "tests/test_security_fixes.py",
            "-v",
            "--tb=short",
            "-q"
        ]
        
        success, output = self.run_scan("pytest", command)
        
        # Parse output
        if "passed" in output:
            import re
            match = re.search(r"(\d+) passed", output)
            if match:
                passed = int(match.group(1))
                print(f"  ✅ {passed} security tests passed")
                self.results['tests'] = 'PASSED'
            else:
                self.results['tests'] = 'UNKNOWN'
        else:
            self.results['tests'] = 'FAILED'
        
        return success
    
    def generate_report(self):
        """Generate security scan report"""
        print("\n" + "="*70)
        print("🔒 SECURITY SCAN REPORT")
        print("="*70)
        
        print("\nResults:")
        for tool, status in self.results.items():
            icon = "✅" if status == 'PASSED' else "⚠️" if status == 'FAILED' else "❓"
            print(f"  {icon} {tool.upper(): <20} {status}")
        
        if self.errors:
            print("\nErrors:")
            for error in self.errors:
                print(f"  ⚠️  {error}")
        
        # Summary
        passed = sum(1 for v in self.results.values() if v == 'PASSED')
        total = len(self.results)
        
        print(f"\nSummary: {passed}/{total} checks passed")
        
        if passed == total:
            print("\n✅ All security checks passed! Ready to commit.")
            return True
        else:
            print("\n❌ Some security checks failed. Fix issues before committing.")
            return False
    
    def run_full_scan(self) -> bool:
        """Run comprehensive security scan"""
        print("\n🔒 PPMAP Security Scan\n")
        
        # Always run
        self.check_custom_security()
        self.check_secrets()
        self.check_tests()
        
        # Optional full scans
        if self.full:
            print("\n📊 Running full security analysis...")
            self.check_dependencies()
            self.check_bandit()
        
        # Generate report
        return self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description="PPMAP Security Scanner"
    )
    parser.add_argument('--full', action='store_true', 
                       help='Run comprehensive scan')
    parser.add_argument('--fix', action='store_true',
                       help='Auto-fix issues where possible')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(
        full=args.full,
        fix=args.fix,
        verbose=args.verbose
    )
    
    success = scanner.run_full_scan()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
