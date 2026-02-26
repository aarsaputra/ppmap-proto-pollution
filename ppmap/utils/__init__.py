"""PPMAP Utilities Package

This package provides utility functions and decorators for PPMAP:
- normalize_url: URL normalization
- rate_limited: Rate limiting decorator  
- retry_request: Retry decorator with exponential backoff
"""

import time
import functools
import logging
from typing import Callable, Optional, Tuple, Type, Union

logger = logging.getLogger(__name__)


# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimiter:
    """Rate limiter to control the frequency of network requests."""

    def __init__(
        self, requests_per_minute: Optional[int] = None, delay_seconds: float = 0.0
    ):
        self.min_interval = 0.0

        if requests_per_minute and requests_per_minute > 0:
            self.min_interval = 60.0 / requests_per_minute
        elif delay_seconds > 0:
            self.min_interval = delay_seconds

        self.last_request_time = 0.0

    def wait(self):
        """Wait if necessary to respect the configured rate limit."""
        if self.min_interval <= 0:
            return

        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

        self.last_request_time = time.time()


def rate_limited(requests_per_minute: int = 60):
    """
    Decorator to rate-limit function calls to specified requests per minute.

    Args:
        requests_per_minute: Maximum requests per minute (default: 60)

    Usage:
        @rate_limited(requests_per_minute=10)
        def my_function():
            pass
    """
    limiter = RateLimiter(requests_per_minute=requests_per_minute)

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait()
            return func(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================================
# RETRY LOGIC
# ============================================================================

def retry_request(
    max_attempts: int = 3,
    backoff: float = 2.0,
    backoff_type: str = "exponential",
    exceptions: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception,
):
    """
    Retry a function with exponential backoff on specified exceptions.

    Args:
        max_attempts: Maximum number of execution attempts.
        backoff: Base delay between retries in seconds.
        backoff_type: 'exponential' or 'linear'.
        exceptions: Tuple of exception types that trigger a retry.

    Usage:
        @retry_request(max_attempts=3, backoff=2.0)
        def make_request():
            pass
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        logger.error(
                            f"Max retries ({max_attempts}) reached for {func.__name__}"
                        )
                        raise

                    if backoff_type == "exponential":
                        delay = backoff ** (attempt - 1)
                    else:  # linear
                        delay = backoff * attempt

                    logger.warning(
                        f"Attempt {attempt} failed for {func.__name__}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    time.sleep(delay)

        return wrapper

    return decorator


# ============================================================================
# URL UTILITIES
# ============================================================================

def normalize_url(url: str) -> str:
    """
    Normalize a URL by removing trailing slashes and encoding special characters.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL

    Examples:
        >>> normalize_url("https://example.com/")
        "https://example.com"
        >>> normalize_url("https://example.com:8080")
        "https://example.com:8080"
    """
    if not url:
        return ""

    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Remove trailing slashes from non-root paths
    if url.count('/') > 3:  # More than "https://host/"
        url = url.rstrip('/')

    return url


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'normalize_url',
    'rate_limited',
    'retry_request',
    'RateLimiter',
]
