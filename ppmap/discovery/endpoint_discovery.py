"""
Endpoint discovery and crawling mechanisms
"""
import logging
import urllib.parse
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import requests
import warnings

logger = logging.getLogger(__name__)

class EndpointDiscovery:
    """Discover endpoints and parameters for testing"""

    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by stripping query parameter values to avoid testing ?id=1 and ?id=2 independently"""
        parsed = urllib.parse.urlparse(url)
        params = sorted([(k, "") for k, v in urllib.parse.parse_qsl(parsed.query)])
        normalized_query = urllib.parse.urlencode(params)
        return parsed._replace(query=normalized_query).geturl()

    def discover_endpoints(self, base_url: str, depth=1, max_endpoints=50):
        """Crawl and discover endpoints"""
        discovered = set()
        to_visit = [base_url]
        visited = set()

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        visited_normalized = set()

        while to_visit and len(discovered) < max_endpoints and depth >= 0:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                # Removed verify=False for general use; using self.session handles it
                # if configured properly in caller logic
                # However, original app uses verify=self.session.verify typically. Let's just pass verify=False to follow original logic which did so manually
                resp = self.session.get(
                    current_url, timeout=self.timeout, verify=False
                )
                if resp.status_code != 200:
                    continue

                # Add self
                discovered.add(current_url)

                # Parse for JS Links (fetch, axios, window.location)
                import re
                js_endpoints = re.findall(r'[\'"](/api/v[0-9]+/[^\'"]+)[\'"]', resp.text)
                for ep in js_endpoints:
                    full_url = urljoin(base_url, ep)
                    normalized_url = self._normalize_url(full_url)
                    if normalized_url not in visited_normalized and urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                        discovered.add(full_url)
                        visited_normalized.add(normalized_url)
                        # We don't necessarily want to visit API endpoints in discovery to crawl further, but we want to store them.

                # Parse for links
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    href = link.get("href")
                    if not href.startswith("javascript:") and not href.startswith("#"):
                        full_url = urljoin(base_url, href)
                        # Keep same domain
                        if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                            normalized_url = self._normalize_url(full_url)
                            if normalized_url not in visited_normalized:
                                discovered.add(full_url)
                                visited_normalized.add(normalized_url)
                                to_visit.append(full_url)

            except Exception as e:
                logger.debug(f"Discovery error on {current_url}: {e}")

            depth -= 1

        return list(discovered)
