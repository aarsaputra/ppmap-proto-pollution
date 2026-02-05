from typing import Optional, Dict
import requests
from bs4 import BeautifulSoup


def discover_csrf_field(html_text: str) -> Optional[Dict[str, str]]:
    """Try to discover a CSRF token field name and value from HTML forms.
    Returns dict {'name':..., 'value':...} or None."""
    try:
        soup = BeautifulSoup(html_text, 'html.parser')
        # Look for common CSRF input names
        candidates = ['csrf_token', 'csrf', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
        for inp in soup.find_all('input'):
            name = inp.get('name')
            if not name:
                continue
            if name.lower() in candidates or 'csrf' in name.lower():
                return {'name': name, 'value': inp.get('value', '')}
        # Fallback: meta tag
        meta = soup.find('meta', attrs={'name': 'csrf-token'})
        if meta and meta.get('content'):
            return {'name': 'csrf-token', 'value': meta.get('content')}
    except Exception:
        return None
    return None


def login_request(session: requests.Session, login_url: str, username: str, password: str,
                  username_field: str = 'username', password_field: str = 'password',
                  extra_fields: Optional[Dict[str, str]] = None) -> bool:
    """Perform a login using requests.Session. Attempts to discover CSRF token automatically.
    Returns True on 2xx/3xx response else False."""
    extra_fields = extra_fields or {}
    try:
        r = session.get(login_url, timeout=15)
    except Exception:
        return False

    csrf = discover_csrf_field(r.text)

    data = {}
    data.update(extra_fields)
    if csrf and csrf.get('name'):
        data[csrf['name']] = csrf.get('value', '')

    data[username_field] = username
    data[password_field] = password

    try:
        post = session.post(login_url, data=data, allow_redirects=True, timeout=15)
        return post.status_code < 400
    except Exception:
        return False


def transfer_cookies_to_driver(session: requests.Session, driver, domain: str):
    """Transfer cookies from requests `session` to Selenium `driver` for a given domain.
    Domain should be like 'https://example.com'. The driver must have visited the domain first.
    """
    try:
        # Selenium requires domain without path when adding cookies; ensure driver at domain
        for c in session.cookies:
            cookie = {
                'name': c.name,
                'value': c.value,
                'path': c.path or '/',
                'domain': c.domain if c.domain and c.domain.startswith('.') else None,
            }
            try:
                # Remove None values
                cookie = {k: v for k, v in cookie.items() if v is not None}
                driver.add_cookie(cookie)
            except Exception:
                continue
    except Exception:
        return
