# PPMAP Limitations & Operational Boundaries

PPMAP (Prototype Pollution Multi-Purpose Assessment Platform) is designed to be a comprehensive testing toolkit. However, like any automated security scanner, it has specific technical limitations. Transparency regarding these boundaries is critical for professional security assessments.

## 1. Deletion-Based Prototype Pollution Detection

**Limitation:** PPMAP currently relies exclusively on **Injection Gadgets** for automated detection. It cannot verify purely **Deletion-Based** Prototype Pollution.

**Context:** Certain vulnerabilities (e.g., Lodash `_.unset` and `_.omit`) allow an attacker to delete prototype properties (e.g., removing `isAdmin` to trigger a fallback).
- PPMAP accurately identifies the presence of vulnerable methods (like `_.unset`) in the source code.
- PPMAP injects a standard validation payload (`polluted` key).
- PPMAP **does not** and **cannot** verify if a deletion payload (`{"constructor":{"prototype":{"isAdmin":undefined}}}`) actually succeeded, because verifying deletion requires deep context about what specific properties the target application relies upon for its internal logic.

**Recommendation:** When PPMAP detects functions known for deletion pollution, analysts must perform manual behavioral testing to confirm exploitability.

## 2. Deep DOM XSS Execution Contexts

**Limitation:** The internal Chrome/Selenium driver may fail to execute highly asynchronous or deeply nested UI components.

**Context:** PPMAP uses Selenium to simulate user interaction and hook `alert`, `prompt`, and `confirm` dialogs.
- If an XSS payload triggers only after a specific sequence of complex DOM interactions (e.g., clicking three modals deep inside a React application), the automated scanner might miss it.
- PPMAP focuses on initial load execution and immediate form submissions.

**Recommendation:** Use the provided PoC scripts from the HTML/Markdown reports and execute them manually in the browser console (F12) to verify complex execution contexts.

## 3. Server-Side Sink Blindness

**Limitation:** Non-reflective Server-Side Prototype Pollution without Out-of-Band (OOB) integration will result in False Negatives.

**Context:** If a Node.js server is polluted but does not return the polluted key in the HTTP response, and if the Out-of-Band (OOB) module is not explicitly enabled (`--oob`), PPMAP cannot definitively confirm the pollution.
- PPMAP relies on JSON formatting variations (space pollution) to infer Server-Side pollution when OOB is off. This relies on the Express.js `json spaces` configuration.
- If the server has a custom JSON stringifier, the scanner will be blind.

**Recommendation:** Always utilize the `--oob` flag with a valid `interact.sh` instance when testing black-box backend APIs.

## 4. WAF Bypass Exhaustion

**Limitation:** The WAF bypass engine relies on static mutational constraints.

**Context:** PPMAP includes 50+ WAF bypass variations (e.g., Unicode escapes, Hex encoding, lowercase coercion).
- Advanced Machine Learning WAFs (Next-Gen WAFs) evaluate behavioral anomalies rather than static strings.
- If a Next-Gen WAF continually drops the connection based on TLS fingerprints or behavioral scoring, PPMAP's string-level bypasses will be ineffective.

**Recommendation:** Run PPMAP with the `--stealth` flag and utilize proxy rotation if testing behind highly aggressive perimeter defenses.

---

*This document ensures security researchers and engineers understand what PPMAP guarantees versus what requires manual validation.*
