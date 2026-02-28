# PPMAP Changelog

All notable changes to PPMAP (Prototype Pollution Multi-Purpose Assessment Platform) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.1.0] - 2026-02-26 (Phase 7: Enhanced Lab Vulnerabilities) ✅

### New Features - Phase 7: Lab Enhancement
- **Server-Side Template Injection (SSTI) Testing**
  - Added `/api/template` endpoint (POST)
  - Vulnerable EJS template rendering with user input
  - Prototype pollution integration with template data
  - Coverage: Tier 9 - Advanced Injection Vectors
- **DOM-based XSS with Prototype Pollution**
  - Added `/dom-xss` endpoint (GET)
  - Interactive testing interface with 4 test vectors
  - Gadget chain demonstrations (addEventListener, setTimeout, eval, Function)
  - Client-side PP exploitation via query parameters
- **Lab Version Upgrade**
  - ppmap_lab v2.2.0 → v2.3.0
  - Endpoints: 24 → 26 (+2 new endpoints)
  - Tiers: 8 → 9 (+1 new tier)
  - Detection Methods: 32 → 34 (+2 new methods)
  - Coverage improved from 75-80% to 85-90%+

### Testing - Phase 7: Validation
- ✅ SSTI endpoint tested and verified working
- ✅ DOM-based XSS endpoint tested and verified working
- ✅ PPMAP scan executed on enhanced lab (12 vulnerabilities found)
- ✅ All 26 endpoints operational
- ✅ GraphQL and WebSocket integration still functional
- ✅ Report generation working with new endpoints

### Documentation - Phase 7: Updates
- Updated CHANGELOG.md with new features
- Updated ppmap_lab health check endpoint
- Updated server startup banner with v2.3.0 info
- ppmap_lab/README.md: Added SSTI and DOM-XSS documentation

---

## [4.1.0] - 2026-02-26 (Phase 6: Tools Security Hardening) ✅

### Security Fixes - Phase 6: Tools Hardening
- **Path Traversal Protection** - `analyze_scan_results.py`
  - Added `validate_file_path()` function with directory restriction
  - `--allowed-dir` parameter to restrict file access
  - Security logging for traversal attempts
- **Markdown Injection Prevention** - `generate_full_report.py`
  - Added `escape_markdown()` function for safe payload escaping
  - Escapes backticks, asterisks, underscores, brackets, hashes
  - Auto-detection of report title and output filename
- **JavaScript Error Handling** - `quickpoc_local.py`
  - Complete JavaScript code with proper try/catch blocks
  - Added `validate_url()` function for URL validation
  - Better error messages and logging

### Improvements - Phase 6: Tools Hardening
- **Logging Framework** - All tools
  - `analyze_reports.py` - Added comprehensive logging
  - `analyze_scan_results.py` - Added security event logging
  - `find_library_issues.py` - Added pattern and result logging
  - `generate_full_report.py` - Added report generation logging
  - `quickpoc_local.py` - Added execution and error logging
- **Exception Handling** - Replaced bare exceptions
  - Specific exceptions (FileNotFoundError, JSONDecodeError, etc.)
  - Context-aware error messages
  - Proper logging with exc_info=True for debugging
- **Module Structure** - Unified utilities
  - Merged `ppmap/utils.py` and `ppmap/utils/` submodules
  - Created unified `ppmap/utils/__init__.py`
  - Exports: normalize_url, rate_limited, retry_request
- **Documentation** - Added comprehensive guides
  - `TOOLS_AUDIT_REPORT.md` - 434-line detailed security audit
  - `TOOLS_TESTING_REPORT.md` - Complete testing validation
  - `tools/tool_template.py` - Reusable template with best practices

### Testing - Phase 6: Validation
- ✅ All 5 major tools tested against ppmap_lab
- ✅ 188 real scan reports processed without errors
- ✅ Path traversal protection verified (blocked /etc/passwd)
- ✅ Diff functionality validated with real reports
- ✅ Markdown report generation: 117KB comprehensive report
- ✅ Security logging: All events properly recorded
- ✅ Lab integration: Detected 10 vulnerabilities in localhost:3000

### Migration Notes
- **Backward Compatible** - All existing command-line flags work
- **Module Change** - `ppmap/utils.py` → `ppmap/utils/__init__.py`
  - Old file renamed to `ppmap/utils_old.py` (backup)
  - All imports automatically resolve to new location
- **Logging** - Tools now create `ppmap_tools.log`
  - Previous unlogged operations now have full audit trail
  - DEBUG level available with verbose flags

---

## [4.1.0] - 2026-02-25 (Phase 1 & 2 Complete)

### Added - Phase 1: Stabilization ✅
- **False Positive Reduction Engine** (`ppmap/fp_engine.py`)
  - `FalsePositiveEngine` class with secondary verification
  - `is_reflected_param()` - Detects reflection vs pollution
  - `calculate_confidence()` - Scoring system (0-100)
  - `filter_findings()` - Separates confirmed from FP
- **Performance Optimization** (`ppmap/performance.py`)
  - `DynamicWorkerScaler` - Auto CPU/memory scaling
  - `adaptive_parallel_map()` - Concurrent scan execution
  - System resource monitoring
- **Unit Test Coverage** - 97 tests (100% pass rate)
  - `test_fp_engine.py` (25 tests)
  - `test_performance.py` (16 tests)
  - `test_graphql.py` (10 tests)
  - `test_sast.py` (15 tests)
  - `test_scanner.py` (15 tests)
  - `test_browser.py` (16 tests)
- **Docker Multi-stage Build** - 3-stage Dockerfile (builder/production/dev)

### Added - Phase 2: Expansion ⏳
- **GraphQL PP Scanner** (`ppmap/graphql.py`)
  - `GraphQLScanner` class with endpoint auto-detection
  - Schema introspection support
  - Mutation and query PP injection testing
  - 8 GraphQL-specific payloads
- **WebSocket PP Scanner** (`ppmap/websocket.py`)
  - `WebSocketScanner` with async support
  - Socket.IO, Redux, GraphQL subscription payloads
  - Response pollution analysis
- **SAST Mode** (`ppmap/sast.py`)
  - Static JS analysis without execution
  - 15+ dangerous sink patterns
  - jQuery, Lodash, native JS coverage
  - CVE mapping (CVE-2019-11358, CVE-2018-16487, etc.)
- **Mobile App Scanner** (`ppmap/mobile.py`)
  - `MobileAppScanner` class for APK/IPA analysis
  - Framework detection (React Native, Capacitor, Ionic, Cordova)
  - 9 mobile-specific danger patterns
  - WebView configuration scanning
  - `FridaIntegration` for runtime PP monitoring

### Added - Lab v2.0
- **Tier 7: GraphQL PP** - 6 vulnerable endpoints (3 mutations, 3 queries)
- **Tier 8: WebSocket PP** - Native WS + Socket.IO endpoints
- Lab now at: 20 endpoints, 8 tiers, 32 detection methods

### Changed
- Upgraded to v4.1.0 across codebase
- CI pipeline tests now 100% passing

---

## [4.0.0] - 2026-02-08 (Enterprise Edition)

### Added
- **Stealth Browser Engine** - Automatic anti-bot evasion (User-Agent rotation, hidden webdriver flags)
- **Target-Specific Reports** - Reports now save to `reports/DOMAIN_DATE/` subdirectories
- **Constructor PP Retry Logic** - Improved browser stability with 2-retry mechanism
- **jQuery JS Detection** - Accurate version detection via browser execution
- **OOB Callback Server** - Out-of-band detection capabilities

### Fixed
- Browser navigation "aborted by navigation" errors
- Report generation HTML/JSON defaults
- Version string synchronization across all files

### Changed
- Upgraded to v4.0.0 Enterprise across entire codebase
- Modernized User-Agent strings (Chrome 120.0)
- Improved error handling with graceful fallbacks

---

## [3.5.0] - 2026-01-31

### Added - Phase 1 (Research Gap Features)
- **CORS Header Pollution Detection** - Tests for CORS configuration pollution via prototype
- **Third-Party Library Gadgets** - Detects 6 library-specific gadgets (Google Analytics, GTM, Adobe DTM, Vue.js, DOMPurify, BSON)
- **Storage API Pollution** - Tests localStorage/sessionStorage direct access vulnerabilities
- **Gadget Database Expansion** - Added 17 new properties to `utils/gadgets.py` (total: 40 properties)

### Added - Phase 2 (CVE-Specific Payloads/Gadgets)
- **Lodash Injection Gadget** - Lodash `_.unset` / `_.omit` prototype pollution partial detection
- **CVE-2024-38986** - @75lb/deep-merge RCE via shell property
- **CVE-2020-8203** - Lodash `_.merge` prototype pollution
- **CVE-2019-7609** - Protobufjs `parse()` pollution
- **CVE-2024-21538** - Safe-eval sandbox escape
- **CVE-2024-29216** - Dset library pollution

### Added - Phase 3 (Real-World Bug Bounty Exploits)
- **Kibana Telemetry RCE** - HackerOne #852613 ($10,000 bounty) - Lodash `_.set` exploitation
- **Blitz.js RCE Chain** - CVE-2022-23631 - superjson deserialization to RCE
- **Elastic XSS** - HackerOne #998398 - Prototype pollution to XSS in Kibana

### Added - Lab & Testing
- **ppmap_lab** - Vulnerable Node.js application with 15 endpoints covering all 28 detection methods
- **100% PortSwigger Coverage** - Lab implements all 20 PortSwigger prototype pollution techniques
- **Comprehensive Testing** - Lab testing achieved 86% detection rate (24/28 methods)

### Fixed
- **List Concatenation Bug** - Added None-safe handling with `or []` fallback for all findings
- **Endpoint Discovery** - Increased depth from 1 to 2 for better coverage
- **Navigation Timing** - Improved browser timing for XSS tests (non-critical)

### Changed
- **Detection Methods** - Increased from 21 to 28 (+33%)
- **Code Size** - Increased from 3,480 to 4,158 lines (+19%)
- **Gadget Properties** - Increased from 23 to 40 (+74%)
- **CVE Coverage** - Added 15 CVE-specific detections
- **Documentation** - Updated all docs to reflect v3.5 capabilities

### Documentation
- Updated README.md, QUICKSTART.md, ROADMAP.md, DOCUMENTATION.md to v3.5
- Added Tier 5 & 6 to detection hierarchy
- Created lab testing guide and PortSwigger coverage analysis
- Added comprehensive walkthrough for v3.5 upgrade

---

## [3.4.0] - 2026-01-30

### Added - Tier 4 (Advanced Bypass Techniques)
- **Constructor-based Pollution** - Bypasses `__proto__` filters using `constructor.prototype`
- **Sanitization Bypass** - Recursive filter evasion (`__pro__proto__to__`)
- **Descriptor Pollution** - `Object.defineProperty()` exploitation
- **Blind Gadget Fuzzer** - Brute-force testing of 64 common gadget properties

### Added - Detection Methods
- **React Flight Protocol** - React 19/Next.js serialization pollution
- **SvelteKit Superforms** - SvelteKit form handling vulnerabilities
- **Charset Override** - UTF-7/ISO-2022 charset manipulation
- **fetch() API Pollution** - Browser fetch API configuration pollution
- **Object.defineProperty() Bypass** - Property descriptor manipulation
- **child_process RCE** - Safe detection of Node.js RCE vectors

### Improved
- Enhanced payload database (218+ payloads)
- Better error handling and logging
- Improved progress bars and UX
- Framework detection (jQuery, Express, React, etc.)

---

## [3.3.0] - 2025-12-15

### Added
- **Tier 1 Blind Detection** - JSON spaces overflow, status code override
- **Function.prototype Chain** - Prototype chain pollution detection
- **Persistence Verification** - Cross-request pollution testing
- **WAF Bypass** - 50+ bypass variations

### Improved
- Async concurrent scanning
- HTML/JSON reporting
- Endpoint discovery

---

## [3.2.0] - 2025-11-20

### Added
- **Server-Side PP Detection** - Lodash merge, Node.js object spread
- **DOM XSS + PP** - Combined DOM-based XSS with prototype pollution
- **Confidence Scoring** - Probabilistic vulnerability assessment

---

## [3.1.0] - 2025-10-15

### Added
- **jQuery Prototype Pollution** - CVE-2019-11358 detection
- **POST Parameter Testing** - XSS via POST requests
- **Selenium WebDriver** - Browser automation for client-side testing

---

## [3.0.0] - 2025-09-01

### Added
- Initial release
- Basic prototype pollution detection
- Command-line interface
- Configuration via YAML

---

## Version Statistics

| Version | Release Date | Detection Methods | Code Lines | CVE Coverage | Notable Features |
|---------|--------------|-------------------|------------|--------------|------------------|
| 3.5.0 | 2026-01-31 | 28 | 4,158 | 15 | Phase 1-3 complete, Lab, 100% research coverage |
| 4.0.0 | 2026-02-08 | 28 | 4,970 | 19 | Enterprise, OOB, Stealth, Multi-format reports |
| 4.1.0 | 2026-02-25 | 32 | 4,973 | 19+ | CVE accuracy fix, all 203 tests pass |
| 3.4.0 | 2026-01-30 | 21 | 3,480 | 9 | Tier 4, Advanced bypasses |
| 3.3.0 | 2025-12-15 | 15 | 2,800 | 5 | Tier 1, Blind detection |
| 3.2.0 | 2025-11-20 | 10 | 2,200 | 3 | Server-side PP, DOM XSS |
| 3.1.0 | 2025-10-15 | 6 | 1,500 | 2 | jQuery, POST testing |
| 3.0.0 | 2025-09-01 | 3 | 800 | 1 | Initial release |

---

## Upgrade Guide

### From 3.4.0 to 3.5.0
- All existing features remain compatible
- New detection methods automatically enabled
- No configuration changes required
- Lab available for testing: `cd ppmap_lab && npm install && npm start`

### From 3.3.0 to 3.4.0
- Update `config.yaml` if customized
- New Tier 4 methods require Selenium WebDriver
- Install updated dependencies: `pip install -r requirements.txt`

---

## Contributors

- **Lead Developer**: Security Research Team
- **Research Sources**: PortSwigger, HackerOne, BlackFan, Yuske, PayloadsAllTheThings
- **Special Thanks**: pp-finder contributors, server-side-gadgets researchers

---

## License

This tool is for **AUTHORIZED SECURITY TESTING ONLY**.  
Unauthorized access to systems is ILLEGAL.  
Author assumes NO liability for misuse or damages.

---

**Current Version**: 4.1.0  
**Last Updated**: February 25, 2026  
**Next Release**: v5.0.0 (Planned - AI-powered detection, ML gadget discovery)
