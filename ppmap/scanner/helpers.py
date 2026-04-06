"""
ppmap/scanner/helpers.py - Shared low-level utilities for all tier scanners.

Extracted from scanner/core.py (previously duplicated inline).
All tiers import from here instead of copy-pasting.

Public API:
    safe_execute(func, *args, fallback, timeout, **kwargs)
    progress_iter(iterable, desc, disable)
    Colors  (re-export from ppmap.utils)
    dismiss_alert(driver) → str | None
    get_page_source(driver) → str
    navigate_to(driver, url, wait=1.5) → bool
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

# ── Re-export Colors so tiers only need one import ────────────────────────────
try:
    from ppmap.utils import Colors
except ImportError:
    class Colors:  # pragma: no cover
        RED = GREEN = YELLOW = BLUE = CYAN = RESET = BOLD = ""


# ── tqdm progress bar ─────────────────────────────────────────────────────────
try:
    from tqdm import tqdm as _tqdm
except ImportError:
    _tqdm = None


def progress_iter(iterable: Iterable, desc: str = "Processing", disable: bool = False) -> Iterable:
    """Wrap *iterable* in a tqdm progress bar if available, otherwise pass through."""
    if _tqdm is not None and not disable:
        return _tqdm(
            iterable,
            desc=desc,
            ncols=80,
            leave=False,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        )
    return iterable


# ── Safe execution wrapper ────────────────────────────────────────────────────

def safe_execute(
    func: Callable,
    *args: Any,
    fallback: Any = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Any:
    """Call *func* and catch all exceptions, returning *fallback* on failure.

    Args:
        func:     The callable to execute.
        *args:    Positional arguments forwarded to *func*.
        fallback: Value returned when *func* raises or times out.
        timeout:  Optional wall-clock timeout in seconds. Requires
                  concurrent.futures (stdlib).
        **kwargs: Keyword arguments forwarded to *func*.

    Returns:
        Return value of *func* or *fallback* on any error.
    """
    try:
        if timeout:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                return future.result(timeout=timeout)
        else:
            return func(*args, **kwargs)
    except TimeoutError:
        logger.warning(f"Timeout executing {func.__name__}")
        return fallback
    except ConnectionError as e:
        logger.error(f"Connection error in {func.__name__}: {str(e)[:100]}")
        return fallback
    except Exception as e:
        logger.error(f"Error in {func.__name__}: {type(e).__name__}: {str(e)[:100]}")
        logger.debug(traceback.format_exc())
        return fallback


# ── Selenium browser helpers ──────────────────────────────────────────────────

def dismiss_alert(driver: Any) -> Optional[str]:
    """Dismiss a browser alert/confirm dialog and return its text.

    Returns None if no alert was present.
    """
    try:
        from selenium.common.exceptions import NoAlertPresentException
        alert = driver.switch_to.alert
        text = alert.text
        alert.dismiss()
        return text
    except Exception:
        return None


def get_page_source(driver: Any) -> str:
    """Return the current page source, or empty string on failure."""
    try:
        return driver.page_source or ""
    except Exception:
        return ""


def navigate_to(driver: Any, url: str, wait: float = 1.5) -> bool:
    """Navigate *driver* to *url* and wait briefly for the page to load.

    Returns True on success, False on error.
    """
    import time
    try:
        driver.get(url)
        time.sleep(wait)
        return True
    except Exception as e:
        logger.warning(f"[navigate_to] Failed to load {url}: {e}")
        return False


def execute_js(driver: Any, script: str, *args: Any) -> Any:
    """Execute JavaScript in the current browser context.

    Returns the script's return value, or None on failure.
    """
    try:
        return driver.execute_script(script, *args)
    except Exception as e:
        logger.debug(f"[execute_js] JS execution error: {e}")
        return None
