# PPMAP v3.5 - Quick Start Guide (2024/2025 Research Enhanced)

## 🚀 Installation

```bash
# Clone or navigate to ppmap directory
cd /path/to/ppmap

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 validate_ppmap_v3.py
```

## 💡 Basic Usage

### Quick PoC Mode
```bash
python3 ppmap.py --poc http://target.com
```

### Full Scan
```bash
python3 ppmap.py --scan http://target.com
```

### Multiple Targets
```bash
python3 ppmap.py --scan \
    http://target1.com \
    http://target2.com \
    http://target3.com
```

## 🔧 Advanced Options

### Stealth Mode (Bypass Detection)
```bash
python3 ppmap.py --scan http://target.com \
    --stealth \
    --delay 2 \
    --rate-limit 30
```

### Production Scan (Full Featured)
```bash
python3 ppmap.py --scan http://target.com \
    --stealth \
    --workers 5 \
    --timeout 30 \
    --rate-limit 40 \
    --format json,html,markdown \
    --output ./enterprise_reports \
    --verbose -vv
```

### Custom Configuration
```bash
# Edit config.yaml for your needs
python3 ppmap.py --scan http://target.com \
    --config custom_config.yaml
```

## 📊 Output & Reports

Reports are automatically saved in:
```
reports/
├── domain_YYYYMMDD_HHMMSS/
│   ├── report.json          # Machine-readable findings
│   ├── report.html          # Interactive HTML report
│   └── summary.txt          # Text summary
```

### JSON Report Format
```json
{
  "target": "http://example.com",
  "scanner_version": "3.0",
  "total_findings": 16,
  "findings_by_severity": {
    "CRITICAL": 4,
    "HIGH": 9,
    "MEDIUM": 3,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "type": "jquery_pp",
      "severity": "CRITICAL",
      "name": "jQuery Prototype Pollution",
      "confidence": 0.98,
      "cve": "CVE-2019-11358",
      "verified": true,
      "payload": {"__proto__": {"polluted": true}},
      "discovered_at": "2025-01-22T15:30:45.123456"
    }
  ]
}
```

## 🎯 Key Features

### ✅ Implemented in v3.5
- ✓ **28 detection methods** (100% PortSwigger + Research coverage)
- ✓ **40 gadget properties** (third-party library support)
- ✓ **15 CVE coverage** (real vulnerability validation)
- ✓ **3 bug bounty cases** (Kibana $10k, Blitz.js, Elastic XSS)
- ✓ **6 detection tiers** (Tier 0-6 complete)
- ✓ **Phase 1**: CORS, Third-Party Gadgets, Storage API
- ✓ **Phase 2**: CVE-Specific Payloads (Lodash, deep-merge, Protobufjs, Safe-eval, Dset)
- ✓ **Phase 3**: Real-World Exploits (HackerOne bug bounty cases)
- ✓ Blind Gadget Fuzzer (pp-finder/BlackFan/Yuske integration)
- ✓ Configuration management (YAML)
- ✓ Rate limiting with jitter
- ✓ Stealth headers (anti-bot bypass)
- ✓ Type-safe data structures
- ✓ Modern Chrome driver with anti-detection
- ✓ Comprehensive CLI arguments
- ✓ Safe error handling (specific exceptions)
- ✓ Finding dataclass with serialization
- ✓ **Vulnerable Lab** (ppmap_lab - 15 endpoints, 100% PortSwigger coverage)

### CLI Arguments Reference

```
SCANNING OPTIONS:
  --poc URL                 Quick PoC mode
  --scan URL [URL ...]      Full scan mode
  --timeout N              Request timeout in seconds (default: 15)
  --workers N              Parallel workers (default: 3)
  --headless / --no-headless  Browser mode (default: headless)

STEALTH OPTIONS:
  --stealth                Enable stealth mode
  --delay N                Delay between requests (seconds)
  --rate-limit N           Max requests per minute
  --user-agent STR         Custom User-Agent
  --verify-ssl             Enable SSL verification

FEATURE TOGGLES:
  --disable-jquery-pp      Skip jQuery PP tests
  --disable-xss            Skip XSS tests
  --disable-waf-bypass     Skip WAF bypass tests
  --disable-discovery      Skip endpoint discovery

CONFIGURATION:
  --config FILE            Config file (default: config.yaml)

REPORTING:
  --output DIR             Output directory (default: ./reports)
  --format FMT             Report formats (json,html,markdown)
  --template TPLT          Report template (modern, minimal)
  --no-poc                 Don't include PoC in reports

GENERAL:
  --verbose, -v            Increase verbosity
  --version                Show version
  --help, -h              Show this help
```

## 🔍 CVE Detection Examples

### jQuery 3.4.1 (Vulnerable)
```bash
python3 ppmap.py --scan "http://target.com"
# Detects:
# - CVE-2019-11358: Prototype Pollution
# - CVE-2020-11022: HTML Prefilter XSS
# - CVE-2020-11023: Code Execution
```

### jQuery 3.5.0 (Partially Fixed)
```bash
python3 ppmap.py --scan "http://target.com"
# Detects:
# - CVE-2020-11023: Code Execution (still present)
```

### jQuery 3.5.1+ (Secure)
```bash
python3 ppmap.py --scan "http://target.com"
# Result: Clean (or other vulnerabilities if present)
```

## 🛠️ Configuration (config.yaml)

```yaml
scanning:
  timeout: 15                    # Request timeout
  max_workers: 3                 # Parallel threads
  stealth_mode: false            # Enable stealth
  headless: true                 # Headless browser
  disable_ssl_verify: true       # Skip SSL checks

rate_limiting:
  enabled: false
  requests_per_minute: 60        # Limit requests
  delay_between_requests: 0.5    # Delay in seconds
  random_delay: true             # Add jitter

testing:
  jquery_pp: true                # Test jQuery PP
  xss: true                      # Test XSS
  post_parameters: true          # Test POST
  server_side_pp: true           # Test server-side PP
  waf_bypass: true               # Test WAF bypass
  confidence_scoring: true       # Score findings
  endpoint_discovery: true       # Discover endpoints

reporting:
  format: ["json", "html"]       # Report formats
  output_dir: "./reports"        # Output directory
  include_poc: true              # Include PoC
  template: "modern"             # Template style
```

## 📝 Logging

Logs are automatically saved to `logs/ppmap_YYYYMMDD_HHMMSS.log`

### Enable Debug Logging
```bash
PPMAP_DEBUG=1 python3 ppmap.py --scan http://target.com -vv
```

### Log Levels
- **DEBUG** - Detailed debug information
- **INFO** - General information (default)
- **WARNING** - Warning messages
- **ERROR** - Error messages

## 🔐 Ethical & Legal

⚖️ **Important:**
- ✅ Use only on systems you own or have explicit permission to test
- ✅ Authorized security testing only
- ✅ Follow responsible disclosure
- ❌ Not for unauthorized access
- ❌ Not for any illegal purposes

## 🐛 Troubleshooting

### Chrome driver not found
```bash
pip install webdriver-manager
python3 ppmap.py --scan http://target.com
```

### Config file not found
```bash
# Uses default config if file missing
# Copy config.yaml to same directory or specify with --config
```

### SSL certificate errors
```bash
# For testing only, use:
python3 ppmap.py --scan https://target.com
# (SSL verification is disabled by default for testing)
```

### Timeout issues
```bash
# Increase timeout for slow servers
python3 ppmap.py --scan http://slow-target.com --timeout 30
```

## 📊 Performance Benchmarks

| Task | Time |
|------|------|
| Startup | <2s |
| Config Load | <0.5s |
| Single Target Scan | ~30-60s |
| Report Generation | <2s |
| Multiple Targets (5) | ~3-5min |

## 🎓 Examples

### Example 1: Quick Assessment
```bash
python3 ppmap.py --poc http://example.com
# Output: jQuery PoC verification only
```

### Example 2: Comprehensive Audit
```bash
python3 ppmap.py --scan http://example.com \
    --format json,html \
    --output ./audit_results \
    --verbose
```

### Example 3: Stealthy Penetration Test
```bash
python3 ppmap.py --scan http://target.com \
    --stealth \
    --rate-limit 20 \
    --delay 3 \
    --no-headless \
    -vv
```

## 📞 Support

For issues or questions:
1. Check logs in `logs/` directory
2. Review `UPDATE_SUMMARY_v3.0.md` for detailed changes
3. Run `python3 validate_ppmap_v3.py` to verify installation
4. Check `README.md` for additional documentation

---

**PPMAP v3.5** - The Most Comprehensive PP Scanner (100% PortSwigger Coverage) ✅
