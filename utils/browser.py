import tempfile
import shutil
import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

def get_temporary_chrome_driver(headless=True, extra_args=None):
    """Create a Chrome/Chromium driver with a temporary user-data-dir for isolation.
    Returns (driver, profile_dir) or (None, None) on failure."""
    extra_args = extra_args or []
    profile_dir = tempfile.mkdtemp(prefix="scan_profile_")

    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"--user-data-dir={profile_dir}")
    chrome_options.add_argument("--window-size=1280,720")
    for a in extra_args:
        chrome_options.add_argument(a)

    try:
        # Prefer webdriver_manager if present
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            return driver, profile_dir
        except Exception:
            # Try default service/driver on PATH
            service = Service()
            driver = webdriver.Chrome(service=service, options=chrome_options)
            return driver, profile_dir
    except Exception:
        shutil.rmtree(profile_dir, ignore_errors=True)
        return None, None


def cleanup_browser(driver, profile_dir, wait=0.5):
    """Perform best-effort cleanup: clear storage, cookies, quit driver and remove profile dir."""
    try:
        if driver:
            try:
                # Clear storage and cookies in the page context
                try:
                    driver.execute_script("try{localStorage.clear();sessionStorage.clear();}catch(e){}")
                except Exception:
                    pass
                try:
                    driver.delete_all_cookies()
                except Exception:
                    pass
            finally:
                try:
                    driver.quit()
                except Exception:
                    pass
    finally:
        # Give browser time to release files then remove profile
        time.sleep(wait)
        try:
            if profile_dir and os.path.exists(profile_dir):
                shutil.rmtree(profile_dir, ignore_errors=True)
        except Exception:
            pass
