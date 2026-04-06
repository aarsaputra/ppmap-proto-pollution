"""
Parameter discovery from forms and links
"""
import logging
import requests
from bs4 import BeautifulSoup
from typing import List

logger = logging.getLogger(__name__)

class ParameterDiscovery:
    """Discover parameters from HTML forms and links (non-destructive)."""

    def __init__(
        self,
        session: requests.Session = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def analyze_forms(self, url: str) -> List[str]:
        """Extract parameter names from input fields on the page"""
        found_params = set()
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code != 200:
                return []

            soup = BeautifulSoup(resp.text, "html.parser")
            inputs = soup.find_all(["input", "textarea", "select"])
            for field in inputs:
                name = field.get("name")
                if name:
                    found_params.add(name)
            return list(found_params)
        except Exception as e:
            logger.debug(f"[ParameterDiscovery] Failed to analyze forms on {url}: {e}")
            return []
