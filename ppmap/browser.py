"""Unified browser helper with Selenium and Playwright fallback.

Provides a thin wrapper (`UnifiedBrowser`) that exposes a small subset of
browser APIs used across the scanner code: `get()`, `execute_script()`,
`page_source`, `get_log()`, `get_alert_text()` and `close()`.

The helper will try to create a Selenium WebDriver if available; otherwise
it falls back to Playwright (Chromium). This avoids ChromeDriver / Chrome
version mismatches in environments where Playwright is available.
"""

import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)


class UnifiedBrowser:
    def __init__(
        self,
        backend: str,
        impl: Any,
        playwright_context: Any = None,
        playwright_playwright: Any = None,
    ):
        # backend: 'selenium' or 'playwright'
        self.backend = backend
        self.impl = impl
        self._pw_context = playwright_context
        self._pw = playwright_playwright

    # Navigation
    def get(self, url: str, wait: float = 0):
        if self.backend == "selenium":
            self.impl.get(url)
        else:
            # Playwright: use page.goto
            self.impl.goto(url, wait_until="load", timeout=30_000)
        if wait:
            import time

            time.sleep(wait)

    # Execute arbitrary JS and return result
    def execute_script(self, script: str, *args):
        if self.backend == "selenium":
            return self.impl.execute_script(script, *args)
        else:
            # Wrap arbitrary script into a function for evaluate()
            # Scripts in this project often use `return ...;` so wrapping is safe.
            try:
                wrapped = f"() => {{ {script} }}"
                return self.impl.evaluate(wrapped)
            except Exception:
                # Try evaluate without wrapper as fallback
                return self.impl.evaluate(script)

    @property
    def page_source(self) -> str:
        if self.backend == "selenium":
            return getattr(self.impl, "page_source", "")
        else:
            return self.impl.content()

    def get_log(self, log_type: str = "browser") -> list:
        if self.backend == "selenium":
            try:
                return self.impl.get_log(log_type)
            except Exception:
                return []
        else:
            # Playwright does not provide retrospective logs easily;
            # return empty list to keep callers tolerant.
            return []

    def get_alert_text(self, timeout: float = 1.0) -> Optional[str]:
        if self.backend == "selenium":
            try:
                alert = self.impl.switch_to.alert
                text = alert.text
                try:
                    alert.accept()
                except Exception:
                    pass
                return text
            except Exception:
                return None
        else:
            try:
                # Playwright: wait for dialog event
                dialog = self.impl.wait_for_event("dialog", timeout=int(timeout * 1000))
                text = dialog.message
                try:
                    dialog.accept()
                except Exception:
                    pass
                return text
            except Exception:
                return None

    # timeouts setters (no-op for playwright)
    def set_page_load_timeout(self, t: int):
        if self.backend == "selenium":
            try:
                self.impl.set_page_load_timeout(t)
            except Exception:
                pass

    def set_script_timeout(self, t: int):
        if self.backend == "selenium":
            try:
                self.impl.set_script_timeout(t)
            except Exception:
                pass

    def close(self):
        try:
            if self.backend == "selenium":
                self.impl.quit()
            else:
                try:
                    # Close page/context and browser
                    self._pw_context.close()
                except Exception:
                    pass
                try:
                    self._pw.stop()
                except Exception:
                    pass
        except Exception:
            pass


def get_browser(
    headless: bool = True, timeout: int = 45, stealth: bool = True
) -> Optional[UnifiedBrowser]:
    """Return a UnifiedBrowser instance using Selenium or Playwright fallback.

    - Tries Selenium (webdriver + webdriver_manager) first.
    - If Selenium is unavailable or fails, tries Playwright (Chromium).
    - Returns None if no browser backend is available.
    """
    # Try Selenium first
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager as WDM
        from webdriver_manager.core.os_manager import ChromeType

        opts = Options()
        if headless:
            try:
                opts.add_argument("--headless=new")
            except Exception:
                opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        # Anti-detection: prevent navigator.webdriver leak
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--disable-extensions")
        opts.add_argument("--disable-infobars")
        opts.add_argument("--ignore-certificate-errors")
        opts.add_argument("--window-size=1920,1080")
        # Modern User-Agent (Chrome 131 — matches STEALTH_HEADERS in ppmap.py)
        opts.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        opts.add_experimental_option("useAutomationExtension", False)

        try:
            logger.info("Attempting to use CHROMIUM driver")
            service = Service(WDM(chrome_type=ChromeType.CHROMIUM).install())
        except Exception:
            logger.warning("CHROMIUM driver failed, falling back to GOOGLE driver")
            service = Service(WDM(chrome_type=ChromeType.GOOGLE).install())

        driver = webdriver.Chrome(service=service, options=opts)
        # Remove navigator.webdriver flag via CDP
        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {
                    "source": 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
                },
            )
        except Exception:
            pass  # CDP not available in all drivers
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)
        logger.info("Selenium backend initialized successfully")
        return UnifiedBrowser("selenium", driver)
    except Exception:
        logger.warning("Selenium backend failed to initialize", exc_info=True)
        # Fall through to Playwright
        pass

    # Try Playwright fallback
    try:
        from playwright.sync_api import sync_playwright

        pw_manager = sync_playwright()
        pw = pw_manager.start()
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="Asia/Jakarta",
        )
        page = context.new_page()
        logger.info("Playwright backend initialized successfully")
        # expose evaluate/content/goto compatible API on page
        return UnifiedBrowser(
            "playwright", page, playwright_context=context, playwright_playwright=pw
        )
    except Exception:
        logger.warning("Playwright backend failed to initialize", exc_info=True)
        return None
