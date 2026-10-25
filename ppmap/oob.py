"""OOB detector v2: mode manual yang PASTI jalan + interact.sh best-effort.

Realita: interact.sh modern butuh RSA registration (PyNaCl) dan
https://interact.sh/register lama sudah mati. Solusi pragmatis:
1. OOB_MANUAL: user beri domain sendiri (Burp Collaborator / self-hosted
   interactsh / dnslog dsb) via --oob-url. Payload memakai subdomain canary,
   verifikasi dilakukan user di panel OOB miliknya (korelasi via canary ID).
2. OOB_INTERACTSH: best-effort register ke server kompatibel (self-hosted).
"""
import logging
import random
import string
from typing import List, Dict, Optional

import requests  # dipatch oleh tests (patch('ppmap.oob.requests.get'))

logger = logging.getLogger(__name__)


class OOBDetector:
    """
    Out-of-Band detector dengan 2 mode:
    - manual   : domain OOB disediakan user (default; selalu works)
    - interactsh: auto-register ke server kompatibel (best-effort)
    """

    def __init__(self, oob_url: Optional[str] = None, server_url: str = "https://interact.sh"):
        self.server_url = server_url.rstrip("/")
        self.correlation_id = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=20)
        )
        self.secret_key = None
        self.oob_domain = None
        self.session_valid = False
        self.mode = "interactsh"

        # Mode manual: --oob-url kolaborator.example.com (tanpa skema)
        if oob_url:
            domain = oob_url
            if "://" in domain:
                from urllib.parse import urlparse
                domain = urlparse(domain).netloc or urlparse(domain).path
            self.oob_domain = f"{self.correlation_id}.{domain}"
            self.session_valid = True
            self.mode = "manual"
            logger.info(f"OOB manual mode: canary domain {self.oob_domain}")

    def register(self) -> bool:
        """Manual mode: selalu 'registered'. Interactsh: best-effort register."""
        if self.mode == "manual" and self.oob_domain:
            return True
        try:
            import requests
            response = requests.get(f"{self.server_url}/register", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.correlation_id = data.get("correlation-id", self.correlation_id)
                self.secret_key = data.get("secret-key")
                self.oob_domain = data.get("full-domain")
                self.session_valid = True
                logger.info(f"Registered OOB session: {self.oob_domain}")
                return True
        except Exception as e:
            logger.warning(
                f"Interactsh auto-register gagal ({str(e)[:80]}). "
                f"Gunakan --oob-url <domain-kolaboratormu> untuk mode manual."
            )
        self.session_valid = False
        return False

    def poll(self) -> List[Dict]:
        """Poll interactions. Manual mode: tidak ada API polling (cek panel sendiri)."""
        if not self.session_valid:
            return []
        if self.mode == "manual":
            logger.debug("OOB manual: cek interaksi di panel kolaborator milikmu.")
            return []
        try:
            import requests
            from urllib.parse import urlencode
            params = {"id": self.correlation_id, "secret": self.secret_key}
            url = f"{self.server_url}/poll?{urlencode(params)}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("data", []) or []
        except Exception as e:
            logger.debug(f"Poll missed: {e}")
        return []

    def get_payload_domain(self) -> str:
        return self.oob_domain if self.oob_domain else "your-oob-server.com"
