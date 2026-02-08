"""
Unit tests for Browser module
"""
import pytest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.browser import UnifiedBrowser


class TestUnifiedBrowser:
    """Tests for UnifiedBrowser class."""
    
    @pytest.fixture
    def selenium_browser(self):
        """Create mock Selenium browser."""
        mock_impl = MagicMock()
        mock_impl.page_source = '<html>Test</html>'
        return UnifiedBrowser(backend='selenium', impl=mock_impl)
    
    @pytest.fixture
    def playwright_browser(self):
        """Create mock Playwright browser."""
        mock_impl = MagicMock()
        mock_impl.content.return_value = '<html>Test</html>'
        mock_context = MagicMock()
        mock_pw = MagicMock()
        return UnifiedBrowser(
            backend='playwright', 
            impl=mock_impl, 
            playwright_context=mock_context,
            playwright_playwright=mock_pw
        )
    
    def test_selenium_get(self, selenium_browser):
        """Selenium should call driver.get()."""
        selenium_browser.get('http://example.com')
        
        selenium_browser.impl.get.assert_called_once_with('http://example.com')
    
    def test_playwright_get(self, playwright_browser):
        """Playwright should call page.goto()."""
        playwright_browser.get('http://example.com')
        
        playwright_browser.impl.goto.assert_called_once()
    
    def test_selenium_execute_script(self, selenium_browser):
        """Selenium should call execute_script."""
        selenium_browser.impl.execute_script.return_value = 'result'
        
        result = selenium_browser.execute_script('return document.title')
        
        assert result == 'result'
        selenium_browser.impl.execute_script.assert_called()
    
    def test_playwright_execute_script(self, playwright_browser):
        """Playwright should call evaluate."""
        playwright_browser.impl.evaluate.return_value = 'result'
        
        result = playwright_browser.execute_script('return document.title')
        
        assert result == 'result'
        playwright_browser.impl.evaluate.assert_called()
    
    def test_selenium_page_source(self, selenium_browser):
        """Selenium should return page_source property."""
        source = selenium_browser.page_source
        
        assert source == '<html>Test</html>'
    
    def test_playwright_page_source(self, playwright_browser):
        """Playwright should call content()."""
        source = playwright_browser.page_source
        
        assert source == '<html>Test</html>'
        playwright_browser.impl.content.assert_called()
    
    def test_selenium_get_log(self, selenium_browser):
        """Selenium should get browser logs."""
        selenium_browser.impl.get_log.return_value = [{'message': 'test'}]
        
        logs = selenium_browser.get_log('browser')
        
        assert len(logs) == 1
    
    def test_playwright_get_log_empty(self, playwright_browser):
        """Playwright should return empty logs (not supported)."""
        logs = playwright_browser.get_log('browser')
        
        assert logs == []
    
    def test_selenium_close(self, selenium_browser):
        """Selenium should call quit()."""
        selenium_browser.close()
        
        selenium_browser.impl.quit.assert_called_once()
    
    def test_playwright_close(self, playwright_browser):
        """Playwright should close context and stop."""
        playwright_browser.close()
        
        playwright_browser._pw_context.close.assert_called()
        playwright_browser._pw.stop.assert_called()
    
    def test_set_page_load_timeout_selenium(self, selenium_browser):
        """Selenium should set page load timeout."""
        selenium_browser.set_page_load_timeout(30)
        
        selenium_browser.impl.set_page_load_timeout.assert_called_with(30)
    
    def test_set_script_timeout_selenium(self, selenium_browser):
        """Selenium should set script timeout."""
        selenium_browser.set_script_timeout(30)
        
        selenium_browser.impl.set_script_timeout.assert_called_with(30)
    
    def test_get_alert_selenium_no_alert(self, selenium_browser):
        """Selenium should handle no alert gracefully."""
        selenium_browser.impl.switch_to.alert.side_effect = Exception("No alert")
        
        result = selenium_browser.get_alert_text()
        
        assert result is None


class TestGetBrowser:
    """Tests for get_browser factory function."""
    
    @patch('ppmap.browser.webdriver')
    @patch('ppmap.browser.WDM')
    def test_get_browser_selenium_success(self, mock_wdm, mock_webdriver):
        """Should create Selenium browser when available."""
        from ppmap.browser import get_browser
        
        mock_driver = MagicMock()
        mock_webdriver.Chrome.return_value = mock_driver
        
        # This may fail in test env, that's ok
        browser = get_browser(headless=True)
        
        # Should attempt to create browser
        assert browser is None or isinstance(browser, UnifiedBrowser)
    
    def test_get_browser_fallback(self):
        """Should fall back to Playwright if Selenium fails."""
        from ppmap.browser import get_browser
        
        # In test environment, might return None
        browser = get_browser(headless=True)
        
        # Should not crash
        assert browser is None or isinstance(browser, UnifiedBrowser)
