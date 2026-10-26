# PPMAP Changelog

All notable changes to PPMAP (Prototype Pollution Multi-Purpose Assessment Platform) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.5.1] - 2026-10-26 (Gadget Library & Auto Reach-Annotation) ✅

### Added
- **`ppmap/payloads/gadget_library.py`**: 36 vektor gadget client-side dari riset
  komunitas (BlackFan/client-side-prototype-pollution, Johan Carlsson intigriti
  0124, s1r1us, Bentkowski, Kinugawa) + 18 fingerprint library (DOMPurify,
  sanitize-html, js-xss, reCAPTCHA, hCaptcha, GTM, Segment, Pendo, Knockout,
  Zepto, Vue, Lodash-client, i18next, Popper, Tealium, Akamai boomerang,
  Marionette, Closure, purl/CVE-2021-20089, dll).
- **Auto gadget vectors di `--reach-check`**: fingerprint halaman → library
  terdeteksi → vektor gadget spesifik otomatis diujikan (`kind=gadget`).
- **Reach-annotation otomatis di `--scan`** [AUDIT-18]: setiap finding jQuery
  versi-based diberi label `reach_verified` = VERIFIED_EXECUTION /
  REACHABLE_FROM_URL / LIBRARY_VULNERABLE_ONLY (+peringatan "JANGAN dilaporkan"
  bila library-only). Laporan tak lagi membingungkan library rentan vs bisa diserang.
- **CVEDatabase +9 CVE di 6 kategori baru**: lodash_extra (CVE-2025-13465,
  CVE-2026-2950, CVE-2026-4800), protobufjs (CVE-2022-25878, CVE-2023-36665),
  dojo (CVE-2020-5259), utils_extend (CVE-2024-57077), synchrony (CVE-2023-45811),
  jsgui (CVE-2022-25301). Total 22 CVE di 9 kategori; jQuery 3.6.0 tetap bersih.
- **Lab permanen** `lab/`: gql_server (8901), ws_server (8902), gadget_server
  multi-page attr/purify/recaptcha (8903), www/ (positive/negative), README.
  Terbukti reach per-gadget 3/3 REACHABLE_FROM_URL (AUDIT-19).

### Fixed
- [AUDIT-20] `--scan --stdin` kini menulis JSONL 1-objek-per-baris (pipeline aman).
- [AUDIT-21] fingerprint gadget library spesifik — deteksi jQuery false-positive
  tidak lagi memicu vektor gadget yang tidak relevan.
- [AUDIT-22] substitusi token `{xs}` di 5 vektor gadget + encoding karakter
  merusak URL pada key/value (spasi, `<`, `>`, `"`, `#`) — sebelumnya payload
  tidak pernah terkirim utuh.
- `UnifiedBrowser.current_url` property (dipakai reach-annotation).

### Verification (2026-10-26)
- pytest **315 passed / 0 failed**
- reach lab: `/attr` 4-hit, `/purify` 2-hit, `/recaptcha` 2-hit, semua REACHABLE_FROM_URL
- `--scan` lab: `[*] Reach verdict` muncul di output scan biasa

---

## [4.5.0] - 2026-10-25 (Verdict Integrity & CLI Reliability Edition) ✅

### Added
- **`--reach-check` Mode (Canary Taint Tracking)**: 3-tier verdict yang membedakan
  temuan berbasis versi dari eksploitasi nyata:
  - Tier 1 `LIBRARY_VULNERABLE_ONLY` — library rentan ada, TIDAK ada jalur URL → sink
  - Tier 1.5 `SINK_SEES_PROTO_STRING` — sink menerima string `__proto__` saja
  - Tier 2 `REACHABLE_FROM_URL` — canary dari query/hash SAMPAI sink
  - Tier 3 `VERIFIED_EXECUTION` — payload dieksekusi nyata di browser
  - Teknik: instrumentasi sink pra-navigasi via CDP
    (`addScriptToEvaluateOnNewDocument`) + `defineProperty` trap di
    `window.jQuery`/`$` (menangkap library yang termuat belakangan) +
    canary unik per-scan. 8 vektor URL: hash-JSON proto/ctor, query bracket,
    query JSON, hash/query HTML (gadget `$(string)` khas jQuery <1.9).
- **`--reach-check` juga menginstrumentasi `jQuery.parseJSON`, `jQuery.fn.html`,
  `jQuery.fn.init` (deteksi HTML-string), `window.eval`, dan setter `innerHTML`.
- **`--oob-url` (OOB Manual Mode)**: gunakan Burp Collaborator / self-hosted
  interactsh / dnslog sendiri. Canary `<id>.<domain-mu>`; interaksi dicek di
  panel milikmu. Interactsh auto-register menjadi best-effort fallback
  (API `/register` publik lama sudah mati — butuh RSA/PyNaCl).
- **`--browser firefox`**: Selenium geckodriver (auto-fallback ke Chrome bila
  geckodrive tidak ada) + Playwright firefox fallback. Proxy & UA didukung.

### Fixed — 10 flag CLI yang diterima tapi tidak pernah dieksekusi (dead flags)
- **`--poc` / `--quickpoc-local`**: argumen ada + fungsi `run_quick_poc()` ada,
  tapi tidak pernah dipanggil di `main()` → sebelumnya hanya print help + exit 0.
  Kini benar-benar menjalankan QuickPoC (2 payload canary, non-destruktif).
- **`--proxy`**: kini dirutekan ke requests session, Selenium
  (`--proxy-server`), Playwright (`proxy.server`), discovery session, dan
  QuickPoC. Terverifikasi: proxy mati menghasilkan `ProxyError` (routing jalan).
- **`--user-agent`**: diterapkan di scanner session, discovery session,
  QuickPoC, dan override UA Firefox.
- **`--wordlist FILE`**: path guessing tambahan di EndpointDiscovery
  (di-inject ke antrian crawl).
- **`--endpoints FILE`**: force-scan queue — bekerja dengan `--scan` dan
  `--scan-full` (dulu tidak dieksekusi sama sekali).
- **`--no-asset-discovery`**: toggle nyata untuk spider file JS statis saat
  discovery (default: aktif).

### Fixed - Regressions
- **`Colors` UnboundLocalError**: `from ppmap.utils import Colors` lokal di blok
  reach-check membuat `Colors` menjadi variabel lokal untuk seluruh `main()`
  dan mematahkan pemakaian global sebelum baris tersebut. Kini memakai import
  global dari header.
- **`ppmap.oob.requests`**: modul `requests` kini di-import di level modul agar
  `patch('ppmap.oob.requests.get')` pada test lama tetap bekerja.

### Changed
- **Versi bump 4.4.2 → 4.5.0** (fitur baru + perbaikan luas: minor bump).

### Verification (2026-10-25)
- Lab positif (jQuery 1.4.2 + `$.extend(true,{},JSON.parse(hash))`):
  `--reach-check` = VERIFIED_EXECUTION tier 3 (canary-in-sink +
  Object.prototype polluted + onerror executed), `--poc` = CONFIRMED.
- Lab negatif (jQuery 1.4.2 tanpa jalur URL → sink): LIBRARY_VULNERABLE_ONLY.
- Kasus nyata bugs.php.net/bug.php?id=1 (jQuery 1.4.2): LIBRARY_VULNERABLE_ONLY
  — konsisten dengan analisis manual; temuan versi-only, tidak layak dilaporkan
  sebagai vulnerability produktif.
- Firefox backend live: `Selenium Firefox backend initialized (geckodriver)`.
- Proxy routing live: proxy mati → ProxyError (terbukti dirutekan).
- `--endpoints` live: 2 endpoint ekstra masuk antrian scan.
- Test suite: 287 passed / 0 failed (termasuk 13 test baru reach_check).
- Commit: `a94d2c3` (reach-check), `da92688` (dead flags), + bump ini.

---

## [4.4.2] - 2026-04-06 (Clean Architecture & Reliability Edition) ✅

### Added - Clean Architecture Refactor
- **Modular Tier System**: Decoupled the monolithic scanner into 8 independent modules (`tier0_basic` to `tier7_advanced`).
- **Orchestration Layer**: Refactored `core.py` into a lightweight orchestrator that delegates to modular tiers.
- **Service Layer**: Introduced `ppmap.service.scan_service` as the primary entry point for external integrations.
- **Standardized Data Models**: Unified all findings under a robust `Finding` dataclass for consistent reporting.

### Added - Reliability Enhancements (Phase 5)
- **DOM-Aware FP Engine**: Enhanced `fp_engine.py` with `validate_dom_sanitization()` to detect WAF blocking and DOM-level sanitization (e.g., DOMPurify) during verification.
- **Optimized Discovery**: Added URL normalization (deduplication) and regex-based JS API route extraction to `endpoint_discovery.py`.
- **Self-Healing Orchestrator**: Implemented browser crash recovery. The system now automatically recreates the Selenium session if a `WebDriverException` occurs mid-scan.
- **Advanced Logging**: Introduced a dedicated `--debug` flag and per-tier loggers for granular tracing.

### Fixed
- **Serialization Bug**: Resolved `Finding is not JSON serializable` errors by implementing a dict-conversion pipeline in the reporting engine.
- **Attribute Sync**: Fixed runtime `TypeError` crashes by synchronizing all 8 tiers with the updated `Finding` model attributes.
- **Tier 7 Logic**: Fixed a major indentation bug in `tier7_advanced.py` that caused methods to be nested incorrectly.


## [4.4.0] - 2026-03-19 (Advanced Evasion Edition) ✅

### Added - Advanced WAF & CSP Bypasses
- **CSP Script Gadgets**
  - Vue.js template compiler hijacking (`__proto__[template]`)
  - Lodash template execution context via `sourceURL`
  - GitLab / Generic framework `data-path` attribute injection
- **Advanced WAF Evasions (2024-2025)**
  - Akamai ASE dynamic inspection limit bypass via 128KB Garbage Padding (CVE-2025-30143 concept)
  - AWS WAF regex filter evasion via rare DOM event (`onbeforetoggle` on `<button popover>`)
  - Cloudflare strict `eval` filter evasion via `Function(atob(...))`
  - Encoding Bertingkat (Double-encoded HTML Hex Entity bypass)
- **False Positive Reduction**
  - Fixed DOM XSS+PP false positives caused by unrelated site modals (e.g., cookie consents) catching `driver.switch_to.alert`.

### Changed
- Global version bump to **v4.4.0 Enterprise**.

---

## [4.3.2] - 2026-03-18 (Architecture Refactor Edition) ✅

### Added - Scanner Architecture Refactor
- **Discovery vs Scanning Separation**
  - Introduced `--discover`: Recon-only mode for endpoint/parameter mapping.
  - Introduced `--scan`: Targeted-only mode for specific URL assessment (skips crawl).
  - Introduced `--scan-full`: Combined Discovery + Scanning workflow (default behavior optimized).
- **Deduplication Engine**
  - Implemented `visited_urls` tracking to prevent redundant scans and infinite loops.
  - Ensures every unique endpoint is processed exactly once per session.
- **Safety Controls**
  - Added `--max-depth`: Controls crawler recursion depth (default: 1).
  - Added `--max-urls`: Safeguard cap for total unique URLs (default: 100).
- **Version Update Checker**
  - Added `check_for_updates` utility to notify users of new GitHub releases.

### Changed
- Global version bump to **v4.3.2 Enterprise**.
- Optimized reporting to support segmented scanning phases.

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
- Upgraded to v4.3.2 across codebase
- CI pipeline tests now 100% passing

---

## [4.3.2] - 2026-02-08 (Enterprise Edition)

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
- Upgraded to v4.3.2 Enterprise across entire codebase
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
| 4.3.2 | 2026-02-08 | 28 | 4,970 | 19 | Enterprise, OOB, Stealth, Multi-format reports |
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

**Current Version**: 4.4.0  
**Last Updated**: March 24, 2026  
**Next Release**: v5.0.0 (Planned - AI-powered detection, ML gadget discovery)
