# PPMAP Changelog

All notable changes to PPMAP (Prototype Pollution Multi-Purpose Assessment Platform) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Added - Phase 2 (CVE-Specific Payloads)
- **CVE-2025-13465** - Lodash `_.unset` / `_.omit` prototype pollution
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

**Current Version**: 4.0.0 Enterprise  
**Last Updated**: February 8, 2026  
**Next Release**: v4.1.0 (Planned - ML-based detection, Dynamic gadget discovery)
