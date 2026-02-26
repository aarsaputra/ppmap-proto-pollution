# PPMAP Testing Lab - Vulnerable Application

## Overview
Vulnerable Node.js application designed to test all 34 PPMAP detection methods across 9 tiers (v2.3.0).

## Features Covered

### Tier 0 - Standard Detection (7 methods)
- ✅ jQuery Prototype Pollution
- ✅ Server-side PP (Lodash merge)
- ✅ POST XSS via PP
- ✅ DOM XSS + PP

### Tier 1 - Blind Detection (4 methods)
- ✅ JSON Spaces Overflow
- ✅ Status Code Override
- ✅ Function.prototype Chain
- ✅ Persistence Verification

### Tier 2 - Modern Frameworks (3 methods)
- ✅ React Flight Protocol (simulated)
- ✅ SvelteKit Superforms (simulated)
- ✅ Charset Override

### Tier 3 - PortSwigger Techniques (3 methods)
- ✅ fetch() API pollution
- ✅ Object.defineProperty() bypass
- ✅ child_process RCE

### Tier 4 - Advanced Bypass (4 methods)
- ✅ Constructor-based pollution
- ✅ Sanitization bypass
- ✅ Descriptor pollution
- ✅ Blind Gadget Fuzzer

### Tier 5 - Research Gap Features (3 methods)
- ✅ CORS Header Pollution
- ✅ Third-Party Library Gadgets (Google Analytics simulation)
- ✅ Storage API Pollution

### Tier 6 - CVE-Specific & Real-World Exploits (4 methods)
- ✅ CVE-Specific Payloads (Lodash, deep-merge)
- ✅ Kibana Telemetry RCE (simulated)
- ✅ Blitz.js RCE Chain (simulated)
- ✅ Elastic XSS (simulated)

### Tier 7 - GraphQL PP Vulnerabilities (2 methods) ⭐ NEW
- ✅ GraphQL Query/Mutation PP
- ✅ Schema introspection pollution

### Tier 8 - WebSocket PP Vulnerabilities (2 methods) ⭐ NEW
- ✅ Socket.IO event pollution
- ✅ Redux-style action poisoning

### Tier 9 - Advanced Injection Vectors (2 methods) ⭐ NEW
- ✅ Server-Side Template Injection (SSTI) - `/api/template`
- ✅ DOM-based XSS with PP Chains - `/dom-xss`

## Setup

```bash
cd ppmap_lab
npm install
npm start
```

Server will run on: http://localhost:3000

## Testing with PPMAP

```bash
# Full scan
python3 ppmap.py --scan http://localhost:3000

# Specific endpoints
python3 ppmap.py --scan http://localhost:3000/api/merge
python3 ppmap.py --scan http://localhost:3000/api/template
python3 ppmap.py --scan http://localhost:3000/dom-xss
```

## Endpoints (26 total)

| Endpoint | Vulnerability | Type | Tier |
|----------|---------------|------|------|
| `/` | jQuery PP + DOM XSS | GET | 0 |
| `/api/merge` | Lodash _.merge (CVE-2020-8203) | POST | 0, 6 |
| `/api/deep-merge` | deep-merge RCE (CVE-2024-38986) | POST | 6 |
| `/api/child-process` | child_process RCE | POST | 3 |
| `/api/telemetry` | Kibana-style telemetry | POST | 6 |
| `/api/cors` | CORS pollution | POST | 5 |
| `/api/constructor` | Constructor bypass | POST | 4 |
| `/api/sanitize` | Sanitization bypass | POST | 4 |
| `/api/descriptor` | Descriptor pollution | POST | 4 |
| `/api/gadgets` | Blind gadget fuzzing | POST | 4 |
| `/api/storage` | Storage API pollution | GET | 5 |
| `/analytics` | Google Analytics gadget | GET | 5 |
| `/api/template` | **SSTI - EJS** | **POST** | **9** |
| `/dom-xss` | **DOM-based XSS + PP** | **GET** | **9** |
| `/graphql` | GraphQL PP testing | POST | 7 |
| `/ws` | WebSocket PP testing | WS | 8 |

... and 10 more supporting endpoints (jQuery versions, GraphQL, health check, etc.)

## Expected Results

PPMAP should detect vulnerabilities when scanning this lab:
- jQuery PP: 4 vulnerabilities
- Library Gadgets: 6 vulnerabilities
- Elastic XSS: 1 vulnerability
- PP Persistence: 1 vulnerability
- **Total: 12+ vulnerabilities detected** ✅

### Coverage
- **Total Detection Methods:** 34
- **Implemented in Lab:** 26/34 (76%+)
- **Verified by PPMAP:** ✅ All 12 found without false positives

## Safety

⚠️ **WARNING**: This application is INTENTIONALLY VULNERABLE. 
- DO NOT deploy to production
- DO NOT expose to public internet
- Use only in isolated testing environment
- Run in Docker container (recommended)

## Docker Deployment (Recommended)

```bash
docker build -t ppmap-lab .
docker run -p 3000:3000 ppmap-lab
```

## Changelog - v2.3.0 (Latest)

### New Features
- Added Server-Side Template Injection (SSTI) detection endpoint
- Added DOM-based XSS with Prototype Pollution testing page
- Improved tier coverage from 8 to 9 tiers
- Increased detection methods from 32 to 34
- Enhanced startup banner and health check

### Previous Versions
- v2.2.0: Added GraphQL and WebSocket integration
- v2.1.0: Expanded endpoint coverage
- v2.0.0: Initial release with 20 endpoints

## License
Educational purposes only. Use at your own risk.
