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

    def __init__(self, session=None, timeout=10, wordlist=None, discover_assets=True):
        self.session = session or requests.Session()
        self.timeout = timeout
        # FIX: --wordlist (path guesses tambahan selain hasil crawl)
        self.wordlist = wordlist  # list path, mis. ["/admin", "/api/v2/users"]
        # FIX: --no-asset-discovery = False -> spider file JS utk ekstrak endpoint
        self.discover_assets = discover_assets

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

            # FIX: wordlist guessing — inject path dari wordlist user ke antrian
            if self.wordlist and len(to_visit) <= 1:
                parsed_base = urllib.parse.urlparse(base_url)
                origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                for wpath in self.wordlist:
                    wpath = str(wpath).strip()
                    if not wpath or wpath.startswith("#"):
                        continue
                    if not wpath.startswith("/"):
                        wpath = "/" + wpath
                    guess = origin + wpath
                    if self._normalize_url(guess) not in visited_normalized and guess not in visited:
                        to_visit.append(guess)

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

                # FIX: asset discovery — ekstrak endpoint dari file JS statis
                if self.discover_assets:
                    for script in soup.find_all("script", src=True):
                        try:
                            src_url = urljoin(current_url, script["src"])
                        except Exception:
                            continue
                        if urllib.parse.urlparse(src_url).netloc != urllib.parse.urlparse(base_url).netloc:
                            continue
                        if self._normalize_url(src_url) in visited_normalized:
                            continue
                        visited_normalized.add(self._normalize_url(src_url))
                        try:
                            js_resp = self.session.get(src_url, timeout=self.timeout, verify=False)
                            if js_resp.status_code == 200:
                                js_eps = re.findall(r'[\'"](/(?:api|v[0-9]+)/(?:[a-zA-Z0-9_\-/.]+))["\']', js_resp.text)
                                for ep in js_eps:
                                    full_url = urljoin(base_url, ep)
                                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                                        n = self._normalize_url(full_url)
                                        if n not in visited_normalized:
                                            discovered.add(full_url)
                                            visited_normalized.add(n)
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Discovery error on {current_url}: {e}")

            depth -= 1

        return list(discovered)
