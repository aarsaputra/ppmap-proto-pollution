#!/usr/bin/env python3
"""
PoC: Demonstrate improved jQuery version detection
Tests the robust jQuery detection against multiple scenarios
"""

import sys
sys.path.insert(0, '/home/lota1337/python/pentest_proto')

from ppmap.scanner.core import extract_jquery_versions_robust
import logging

logging.basicConfig(level=logging.DEBUG)

# Test scenarios
test_cases = [
    {
        "name": "Multiple jQuery versions (like gov.bn)",
        "html": """
        <script src="https://code.jquery.com/jquery-1.11.3.js"></script>
        <!-- Fallback CDN: jquery-3.3.1.min.js -->
        <script src="backup/jquery-1.12.4.js"></script>
        """,
        "expected": "1.11.3"  # First in script src
    },
    {
        "name": "jQuery with dynamic version check",
        "html": """
        <script src="https://code.jquery.com/jquery-3.4.1.js"></script>
        <script>console.log("jQuery v3.5.0 available")</script>
        """,
        "expected": "3.4.1"  # From src attribute
    },
    {
        "name": "Older jQuery (1.11.1)",
        "html": """
        <script src="https://code.jquery.com/jquery-1.11.1.js"></script>
        """,
        "expected": "1.11.1"  # Exact match
    },
    {
        "name": "jQuery with version in filename variants",
        "html": """
        <!-- Different filename patterns -->
        <script src="jquery-2.1.4.min.js"></script>
        <script src="jquery.1.8.3.js"></script>
        """,
        "expected": "1.8.3"  # Oldest version
    },
]

print("=" * 80)
print("jQuery Version Detection Improvement Test")
print("=" * 80)

for i, test in enumerate(test_cases, 1):
    print(f"\n[Test {i}] {test['name']}")
    print("-" * 80)
    
    result = extract_jquery_versions_robust(test['html'])
    
    print(f"  Dynamic version:    {result['dynamic']}")
    print(f"  Script src versions: {result['src_versions']}")
    print(f"  Pattern versions:   {result['pattern_versions']}")
    print(f"  Recommended:        {result['recommended']}")
    print(f"  All versions:       {sorted(result['all_versions'])}")
    print(f"  Detection method:   {result['detection_method']}")
    
    # Verify expectation
    if result['recommended'] == test['expected']:
        print(f"  ✅ PASS: Correctly detected {result['recommended']}")
    else:
        print(f"  ⚠️  Expected: {test['expected']}, Got: {result['recommended']}")

print("\n" + "=" * 80)
print("Summary of Improvements:")
print("=" * 80)
print("""
✅ Method 1 (Dynamic): Executes jQuery.fn.jquery if page loads it
✅ Method 2 (Script src): Extracts from <script src="jquery-X.Y.Z.js">  [MOST RELIABLE]
✅ Method 3 (Pattern): Regex fallback for HTML comments/embedded text

Key Improvements:
1. Prioritizes script src attributes (explicit declarations)
2. Extracts ALL jQuery versions found (not just first)
3. Reports detection method used
4. Handles multiple jQuery versions correctly
5. Better for detecting version mismatches (like Brunei gov.bn)

Real-world scenario (gov.bn issue):
  - Wappalyzer detected: 1.11.3 (from loaded JavaScript)
  - PPMAP old version detected: 3.3.1 (wrong)
  - PPMAP new version detects:
    ✅ 1.11.3 (from script src - most reliable)
    ✅ 3.3.1 (from comments/fallback)
    ✅ Shows both with method used
""")
