# PPMAP Testing Lab - Vulnerable Application

## Overview
Vulnerable Node.js application designed to test all 28 PPMAP detection methods across 6 tiers.

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
python3 ppmap.py --scan http://localhost:3000/api/deep-merge
python3 ppmap.py --scan http://localhost:3000/api/child-process
```

## Endpoints

| Endpoint | Vulnerability | Tier |
|----------|---------------|------|
| `/` | jQuery PP + DOM XSS | 0 |
| `/api/merge` | Lodash _.merge (CVE-2020-8203) | 0, 6 |
| `/api/deep-merge` | deep-merge RCE (CVE-2024-38986) | 6 |
| `/api/child-process` | child_process RCE | 3 |
| `/api/telemetry` | Kibana-style telemetry | 6 |
| `/api/cors` | CORS pollution | 5 |
| `/api/constructor` | Constructor bypass | 4 |
| `/api/sanitize` | Sanitization bypass | 4 |
| `/api/descriptor` | Descriptor pollution | 4 |
| `/api/gadgets` | Blind gadget fuzzing | 4 |
| `/api/storage` | Storage API pollution | 5 |
| `/analytics` | Google Analytics gadget | 5 |

## Expected Results

PPMAP should detect **all 28 methods** when scanning this lab:
- Tier 0: 7 vulnerabilities
- Tier 1: 4 vulnerabilities
- Tier 2: 3 vulnerabilities
- Tier 3: 3 vulnerabilities
- Tier 4: 4 vulnerabilities
- Tier 5: 3 vulnerabilities
- Tier 6: 4 vulnerabilities

**Total: 28 vulnerabilities detected** ✅

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

## License
Educational purposes only. Use at your own risk.
