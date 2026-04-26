import json
import os
from typing import Dict, List

def parse_json_cookies(file_path: str) -> str:
    """
    Parse a JSON cookie file (exported from browser extensions) 
    and return a semicolon-separated string for the Cookie header.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Cookie file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        cookies_data = json.load(f)
    
    if not isinstance(cookies_data, list):
        raise ValueError("Invalid cookie format: expected a list of cookie objects")
    
    cookie_pairs = []
    for cookie in cookies_data:
        name = cookie.get('name')
        value = cookie.get('value')
        if name and value:
            cookie_pairs.append(f"{name}={value}")
    
    return "; ".join(cookie_pairs)

def load_cookies_to_headers(cookie_file: str, headers: Dict[str, str] = None) -> Dict[str, str]:
    """
    Load cookies from a JSON file and add them to the provided headers dictionary.
    """
    if headers is None:
        headers = {}
    
    try:
        cookie_string = parse_json_cookies(cookie_file)
        if cookie_string:
            # If Cookie header already exists, append or overwrite? 
            # Usually overwrite for fresh auth
            headers['Cookie'] = cookie_string
    except Exception as e:
        # We'll let the caller handle logging
        raise e
        
    return headers
