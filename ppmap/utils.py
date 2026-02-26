"""Utility helpers: safe execute, rate limiter, stealth headers"""

import time
import random
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def safe_execute(
    func: Callable,
    *args,
    timeout: Optional[float] = None,
    fallback: Any = None,
    **kwargs,
):
    """Run func with optional timeout using a ThreadPoolExecutor for safety."""
    if timeout:
        try:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(func, *args, **kwargs)
                return future.result(timeout=timeout)
        except Exception as e:
            logger.debug(f"safe_execute timeout/error: {e}")
            return fallback
    else:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.debug(f"safe_execute error: {e}")
            return fallback


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60, random_jitter: bool = True):
        self.requests_per_minute = requests_per_minute
        self.random_jitter = random_jitter
        self.last = 0
        self.min_interval = 60.0 / max(1, requests_per_minute)

    def wait(self):
        now = time.time()
        elapsed = now - self.last
        to_sleep = self.min_interval - elapsed
        if to_sleep > 0:
            jitter = random.uniform(0.8, 1.2) if self.random_jitter else 1.0
            time.sleep(to_sleep * jitter)
        self.last = time.time()


class StealthHeaders:
    @staticmethod
    def headers(
        user_agent: Optional[str] = None, referrer: Optional[str] = None
    ) -> dict:
        import random

        ua = user_agent or random.choice(
            [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            ]
        )
        h = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "DNT": "1",
        }
        if referrer:
            h["Referer"] = referrer
        return h


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme (defaulting to https)."""
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_section(title):
    print(f"\n{Colors.CYAN}{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}{Colors.ENDC}")
