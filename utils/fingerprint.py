"""
Framework Fingerprinting Module for PPMAP v3.4.0
Auto-detect web frameworks to prioritize relevant payloads
"""

from typing import Optional, Dict, List


# Framework detection signatures
FRAMEWORK_SIGNATURES = {
    "nextjs": {
        "html_patterns": [
            "__NEXT_DATA__",
            "/_next/",
            "__next",
            "NextRouter",
        ],
        "headers": ["x-nextjs-cache", "x-middleware-prefetch"],
        "scripts": ["_next/static"],
    },
    "react": {
        "html_patterns": [
            "react",
            "__REACT_DEVTOOLS",
            "ReactDOM",
            "_reactRootContainer",
            "data-reactroot",
        ],
        "headers": [],
        "scripts": ["react.production.min.js", "react-dom"],
    },
    "svelte": {
        "html_patterns": [
            "svelte_internal",
            "__SVELTE",
            "svelte-",
            "data-svelte",
        ],
        "headers": [],
        "scripts": ["svelte", "@sveltejs"],
    },
    "sveltekit": {
        "html_patterns": [
            "__sveltekit",
            "data-sveltekit",
            "__SVELTEKIT_DATA__",
        ],
        "headers": [],
        "scripts": ["_app/immutable", ".svelte-kit"],
    },
    "vue": {
        "html_patterns": [
            "__VUE__",
            "Vue.version",
            "v-if",
            "v-for",
            "data-v-",
            ":class",
        ],
        "headers": [],
        "scripts": ["vue.global.prod", "vue.runtime"],
    },
    "nuxt": {
        "html_patterns": [
            "__NUXT__",
            "nuxt",
            "_nuxt/",
        ],
        "headers": [],
        "scripts": ["_nuxt/", "nuxt.config"],
    },
    "angular": {
        "html_patterns": [
            "ng-version",
            "angular",
            "ng-app",
            "ng-controller",
            "_ngcontent",
        ],
        "headers": [],
        "scripts": ["angular", "zone.js"],
    },
    "express": {
        "html_patterns": [],
        "headers": ["x-powered-by"],
        "header_values": {"x-powered-by": "Express"},
        "scripts": [],
    },
    "jquery": {
        "html_patterns": [
            "jQuery",
            "$.extend",
            "$(document)",
        ],
        "headers": [],
        "scripts": ["jquery.min.js", "jquery-"],
    },
}


def detect_frameworks(html_content: str, headers: Optional[Dict[str, str]] = None) -> List[Dict]:
    """
    Detect frameworks from HTML content and response headers.
    
    Args:
        html_content: HTML page content
        headers: Optional HTTP response headers
        
    Returns:
        List of detected frameworks with confidence scores
    """
    detected = []
    headers = headers or {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for framework_name, signatures in FRAMEWORK_SIGNATURES.items():
        confidence = 0
        matches = []
        
        # Check HTML patterns
        for pattern in signatures.get("html_patterns", []):
            if pattern.lower() in html_content.lower():
                confidence += 25
                matches.append(f"html:{pattern}")
        
        # Check script patterns
        for pattern in signatures.get("scripts", []):
            if pattern.lower() in html_content.lower():
                confidence += 20
                matches.append(f"script:{pattern}")
        
        # Check headers
        for header in signatures.get("headers", []):
            if header.lower() in headers_lower:
                confidence += 30
                matches.append(f"header:{header}")
        
        # Check header values
        for header, expected_value in signatures.get("header_values", {}).items():
            if headers_lower.get(header.lower(), "").lower() == expected_value.lower():
                confidence += 40
                matches.append(f"header_value:{header}={expected_value}")
        
        # Cap confidence at 100
        confidence = min(confidence, 100)
        
        if confidence > 0:
            detected.append({
                "framework": framework_name,
                "confidence": confidence,
                "matches": matches,
            })
    
    # Sort by confidence descending
    detected.sort(key=lambda x: x["confidence"], reverse=True)
    
    return detected


def get_priority_payloads(detected_frameworks: List[Dict]) -> List[str]:
    """
    Get prioritized payload categories based on detected frameworks.
    
    Args:
        detected_frameworks: List from detect_frameworks()
        
    Returns:
        List of payload categories to prioritize
    """
    priority = []
    
    framework_payload_map = {
        "jquery": ["jquery_extend", "jquery_variations"],
        "react": ["react_flight", "flight_protocol_basic"],
        "nextjs": ["react_flight", "flight_rce_gadgets"],
        "svelte": ["sveltekit_superforms", "devalue_deserialization"],
        "sveltekit": ["sveltekit_superforms", "superforms_pollution", "nodemailer_gadget"],
        "vue": ["constructor_prototype", "object_prototype"],
        "nuxt": ["constructor_prototype", "server_side"],
        "angular": ["dom_gadgets", "template_gadgets"],
        "express": ["express", "nodejs_rce", "json_spaces"],
    }
    
    for detection in detected_frameworks:
        framework = detection["framework"]
        if framework in framework_payload_map:
            priority.extend(framework_payload_map[framework])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_priority = []
    for p in priority:
        if p not in seen:
            seen.add(p)
            unique_priority.append(p)
    
    return unique_priority


def fingerprint_summary(detected_frameworks: List[Dict]) -> str:
    """
    Generate a human-readable fingerprint summary.
    
    Args:
        detected_frameworks: List from detect_frameworks()
        
    Returns:
        Formatted summary string
    """
    if not detected_frameworks:
        return "No frameworks detected"
    
    lines = ["Detected Frameworks:"]
    for d in detected_frameworks:
        lines.append(f"  - {d['framework'].upper()} (confidence: {d['confidence']}%)")
    
    return "\n".join(lines)
