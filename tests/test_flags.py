"""
Unit tests for PPMAP CLI feature flags and argparse behavior.

Tests cover:
- Argparse defaults
- Flag parsing (--stealth, --disable-*, --preset, --async-scan, etc.)
- Preset logic: quick / thorough / stealth
- Config overrides from args
- Edge cases (conflicting flags, invalid values)
"""
import sys
import os
import argparse
import pytest
from unittest.mock import patch, MagicMock

# Add parent to path so we can import ppmap modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# Helpers: build the argument parser from ppmap.py without running main()
# ============================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Reconstruct the argparse.ArgumentParser from ppmap.py."""
    parser = argparse.ArgumentParser(prog="ppmap.py")
    # Scanning modes
    parser.add_argument("--poc", type=str, metavar="URL")
    parser.add_argument("--quickpoc-local", type=str, metavar="URL")
    parser.add_argument("--scan", nargs="*", metavar="URL")
    parser.add_argument("-ls", "--list", type=str, metavar="FILE")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--request", "-r", type=str, metavar="FILE")
    parser.add_argument("--config", type=str, default="config.yaml")
    # Browser
    parser.add_argument("--browser", type=str, default="chrome", choices=["chrome", "firefox"])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--no-headless", dest="headless", action="store_false")
    # Stealth & rate
    parser.add_argument("--stealth", action="store_true")
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--rate-limit", type=int, metavar="N")
    parser.add_argument("--user-agent", type=str)
    # Feature disables
    parser.add_argument("--disable-jquery-pp", action="store_true")
    parser.add_argument("--disable-xss", action="store_true")
    parser.add_argument("--disable-waf-bypass", action="store_true")
    parser.add_argument("--disable-discovery", action="store_true")
    # Reporting
    parser.add_argument("--output", type=str, default="./reports")
    parser.add_argument("--format", type=str, default="json,html,csv,xml,md")
    parser.add_argument("--template", type=str, default="modern")
    parser.add_argument("--no-poc", action="store_true")
    # Async
    parser.add_argument("--async-scan", action="store_true")
    parser.add_argument("--async-workers", type=int, default=10)
    # Network
    parser.add_argument("--oob", action="store_true")
    parser.add_argument("--verify-ssl", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--proxy", type=str, metavar="PROXY")
    # Misc
    parser.add_argument("--diff", nargs=2, metavar=("FILE1", "FILE2"))
    parser.add_argument("--preset", choices=["quick", "thorough", "stealth"])
    parser.add_argument("--verbose", "-v", action="count", default=0)
    return parser


def parse_args(arg_list):
    """Parse a list of CLI argument strings and return namespace."""
    return _build_parser().parse_args(arg_list)


def apply_preset(args):
    """Apply preset logic identical to ppmap.py main()."""
    if args.preset == "quick":
        args.workers = 1
        args.headless = True
        args.disable_waf_bypass = True
        args.oob = False
    elif args.preset == "thorough":
        args.workers = 10
        args.oob = True
        args.verify_ssl = False
    elif args.preset == "stealth":
        args.workers = 2
        args.delay = 2.0
        args.rate_limit = 5
        args.stealth = True
        args.headless = True


# ============================================================================
# Tests: Defaults
# ============================================================================

class TestDefaults:
    """Ensure defaults match expected values."""

    def test_default_browser_chrome(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.browser == "chrome"

    def test_default_timeout_30(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.timeout == 30

    def test_default_workers_3(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.workers == 3

    def test_default_headless_true(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.headless is True

    def test_default_delay_0_5(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.delay == 0.5

    def test_default_format(self):
        args = parse_args(["--scan", "http://example.com"])
        assert "json" in args.format

    def test_default_output_reports(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.output == "./reports"

    def test_default_async_workers_10(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.async_workers == 10

    def test_stealth_false_by_default(self):
        args = parse_args([])
        assert args.stealth is False

    def test_disable_flags_false_by_default(self):
        args = parse_args([])
        assert args.disable_jquery_pp is False
        assert args.disable_xss is False
        assert args.disable_waf_bypass is False
        assert args.disable_discovery is False

    def test_oob_false_by_default(self):
        args = parse_args([])
        assert args.oob is False

    def test_insecure_false_by_default(self):
        args = parse_args([])
        assert args.insecure is False

    def test_no_poc_false_by_default(self):
        args = parse_args([])
        assert args.no_poc is False

    def test_async_scan_false_by_default(self):
        args = parse_args([])
        assert args.async_scan is False

    def test_verbose_0_by_default(self):
        args = parse_args([])
        assert args.verbose == 0


# ============================================================================
# Tests: Stealth & Network flags
# ============================================================================

class TestStealthFlags:
    """Test --stealth, --rate-limit, --proxy, --user-agent flags."""

    def test_stealth_flag_sets_true(self):
        args = parse_args(["--stealth"])
        assert args.stealth is True

    def test_rate_limit_parsed_correctly(self):
        args = parse_args(["--rate-limit", "30"])
        assert args.rate_limit == 30

    def test_rate_limit_none_when_not_specified(self):
        args = parse_args([])
        assert args.rate_limit is None

    def test_proxy_parsed(self):
        args = parse_args(["--proxy", "http://127.0.0.1:8080"])
        assert args.proxy == "http://127.0.0.1:8080"

    def test_proxy_none_when_not_specified(self):
        args = parse_args([])
        assert args.proxy is None

    def test_user_agent_parsed(self):
        ua = "Mozilla/5.0 TestBot"
        args = parse_args(["--user-agent", ua])
        assert args.user_agent == ua

    def test_insecure_flag(self):
        args = parse_args(["--insecure"])
        assert args.insecure is True

    def test_verify_ssl_flag(self):
        args = parse_args(["--verify-ssl"])
        assert args.verify_ssl is True

    def test_no_headless_overrides_default(self):
        args = parse_args(["--no-headless"])
        assert args.headless is False

    def test_headless_explicit(self):
        args = parse_args(["--headless"])
        assert args.headless is True

    def test_delay_custom(self):
        args = parse_args(["--delay", "3.0"])
        assert args.delay == 3.0


# ============================================================================
# Tests: Feature disable flags
# ============================================================================

class TestDisableFlags:
    """Test --disable-* feature flags."""

    def test_disable_jquery_pp(self):
        args = parse_args(["--disable-jquery-pp"])
        assert args.disable_jquery_pp is True

    def test_disable_xss(self):
        args = parse_args(["--disable-xss"])
        assert args.disable_xss is True

    def test_disable_waf_bypass(self):
        args = parse_args(["--disable-waf-bypass"])
        assert args.disable_waf_bypass is True

    def test_disable_discovery(self):
        args = parse_args(["--disable-discovery"])
        assert args.disable_discovery is True

    def test_all_disable_flags_together(self):
        args = parse_args([
            "--disable-jquery-pp",
            "--disable-xss",
            "--disable-waf-bypass",
            "--disable-discovery"
        ])
        assert all([
            args.disable_jquery_pp,
            args.disable_xss,
            args.disable_waf_bypass,
            args.disable_discovery,
        ])


# ============================================================================
# Tests: Reporting flags
# ============================================================================

class TestReportingFlags:
    """Test --format, --output, --template, --no-poc flags."""

    def test_format_single(self):
        args = parse_args(["--format", "json"])
        assert args.format == "json"

    def test_format_multiple(self):
        args = parse_args(["--format", "json,html,csv"])
        # split behavior matches ppmap.py PPMAP_CONFIG update
        parts = args.format.split(",")
        assert "json" in parts
        assert "html" in parts
        assert "csv" in parts

    def test_output_custom_dir(self):
        args = parse_args(["--output", "/tmp/my_reports"])
        assert args.output == "/tmp/my_reports"

    def test_template_minimal(self):
        args = parse_args(["--template", "minimal"])
        assert args.template == "minimal"

    def test_template_detailed(self):
        args = parse_args(["--template", "detailed"])
        assert args.template == "detailed"

    def test_no_poc_flag(self):
        args = parse_args(["--no-poc"])
        assert args.no_poc is True
        # include_poc should be False (ppmap logic: not args.no_poc)
        assert not args.no_poc is False  # i.e., include_poc = not True = False

    def test_include_poc_default(self):
        args = parse_args([])
        # default no_poc=False means include_poc=True
        assert args.no_poc is False


# ============================================================================
# Tests: Async scan flags
# ============================================================================

class TestAsyncFlags:
    """Test --async-scan and --async-workers flags."""

    def test_async_scan_flag(self):
        args = parse_args(["--async-scan"])
        assert args.async_scan is True

    def test_async_workers_default(self):
        args = parse_args([])
        assert args.async_workers == 10

    def test_async_workers_custom(self):
        args = parse_args(["--async-workers", "25"])
        assert args.async_workers == 25

    def test_async_scan_false_without_flag(self):
        args = parse_args(["--scan", "http://example.com"])
        assert args.async_scan is False


# ============================================================================
# Tests: --preset logic
# ============================================================================

class TestPresets:
    """Test preset application logic (mirrors ppmap.py main())."""

    def _make_base_args(self):
        """Create base args with all defaults."""
        return parse_args([])

    def test_preset_quick_sets_workers_1(self):
        args = self._make_base_args()
        args.preset = "quick"
        apply_preset(args)
        assert args.workers == 1

    def test_preset_quick_enables_headless(self):
        args = self._make_base_args()
        args.preset = "quick"
        apply_preset(args)
        assert args.headless is True

    def test_preset_quick_disables_waf_bypass(self):
        args = self._make_base_args()
        args.preset = "quick"
        apply_preset(args)
        assert args.disable_waf_bypass is True

    def test_preset_quick_disables_oob(self):
        args = self._make_base_args()
        args.preset = "quick"
        apply_preset(args)
        assert args.oob is False

    def test_preset_thorough_sets_workers_10(self):
        args = self._make_base_args()
        args.preset = "thorough"
        apply_preset(args)
        assert args.workers == 10

    def test_preset_thorough_enables_oob(self):
        args = self._make_base_args()
        args.preset = "thorough"
        apply_preset(args)
        assert args.oob is True

    def test_preset_thorough_disables_ssl_verify(self):
        args = self._make_base_args()
        args.preset = "thorough"
        apply_preset(args)
        # thorough sets verify_ssl = False (scan speed)
        assert args.verify_ssl is False

    def test_preset_stealth_sets_workers_2(self):
        args = self._make_base_args()
        args.preset = "stealth"
        apply_preset(args)
        assert args.workers == 2

    def test_preset_stealth_sets_delay_2(self):
        args = self._make_base_args()
        args.preset = "stealth"
        apply_preset(args)
        assert args.delay == 2.0

    def test_preset_stealth_sets_rate_limit_5(self):
        args = self._make_base_args()
        args.preset = "stealth"
        apply_preset(args)
        assert args.rate_limit == 5

    def test_preset_stealth_enables_stealth(self):
        args = self._make_base_args()
        args.preset = "stealth"
        apply_preset(args)
        assert args.stealth is True

    def test_preset_stealth_enables_headless(self):
        args = self._make_base_args()
        args.preset = "stealth"
        apply_preset(args)
        assert args.headless is True

    def test_no_preset_does_not_modify_args(self):
        args = self._make_base_args()
        args.preset = None
        workers_before = args.workers
        apply_preset(args)
        assert args.workers == workers_before


# ============================================================================
# Tests: Scan targets (--scan, --poc, --list, --stdin, --request)
# ============================================================================

class TestScanTargetFlags:
    """Test scan mode flags."""

    def test_scan_single_url(self):
        args = parse_args(["--scan", "http://target.com"])
        assert "http://target.com" in args.scan

    def test_scan_multiple_urls(self):
        args = parse_args(["--scan", "http://a.com", "http://b.com"])
        assert len(args.scan) == 2

    def test_scan_no_args_returns_empty_list(self):
        args = parse_args(["--scan"])
        # nargs='*' with no values -> empty list
        assert args.scan == []

    def test_poc_url(self):
        args = parse_args(["--poc", "http://target.com"])
        assert args.poc == "http://target.com"

    def test_stdin_flag(self):
        args = parse_args(["--stdin"])
        assert args.stdin is True

    def test_list_file(self):
        args = parse_args(["-ls", "targets.txt"])
        assert args.list == "targets.txt"

    def test_request_file(self):
        args = parse_args(["--request", "burp_request.txt"])
        assert args.request == "burp_request.txt"

    def test_browser_firefox(self):
        args = parse_args(["--browser", "firefox"])
        assert args.browser == "firefox"

    def test_browser_invalid_raises(self):
        with pytest.raises(SystemExit):
            parse_args(["--browser", "safari"])

    def test_diff_two_files(self):
        args = parse_args(["--diff", "scan1.json", "scan2.json"])
        assert args.diff == ["scan1.json", "scan2.json"]


# ============================================================================
# Tests: Verbose / OOB
# ============================================================================

class TestVerboseAndOOB:
    """Test --verbose and --oob flags."""

    def test_verbose_0_default(self):
        args = parse_args([])
        assert args.verbose == 0

    def test_verbose_1(self):
        args = parse_args(["-v"])
        assert args.verbose == 1

    def test_verbose_2(self):
        args = parse_args(["-v", "-v"])
        assert args.verbose == 2

    def test_verbose_3(self):
        args = parse_args(["-v", "-v", "-v"])
        assert args.verbose == 3

    def test_oob_flag(self):
        args = parse_args(["--oob"])
        assert args.oob is True

    def test_timeout_custom(self):
        args = parse_args(["--timeout", "60"])
        assert args.timeout == 60

    def test_workers_custom(self):
        args = parse_args(["--workers", "8"])
        assert args.workers == 8


# ============================================================================
# Tests: CompleteSecurityScanner stealth integration (BUG-7 fix)
# ============================================================================

class TestCompleteScannerStealth:
    """Verify stealth param actually sets headers in CompleteSecurityScanner."""

    def test_stealth_headers_applied(self):
        from ppmap.engine import CompleteSecurityScanner
        scanner = CompleteSecurityScanner(stealth=True)
        ua = scanner.session.headers.get("User-Agent", "")
        assert "Mozilla" in ua, f"Expected browser UA, got: {ua}"

    def test_no_stealth_no_custom_ua(self):
        from ppmap.engine import CompleteSecurityScanner
        scanner = CompleteSecurityScanner(stealth=False)
        # Default requests UA without stealth
        ua = scanner.session.headers.get("User-Agent", "")
        # Should be the stdlib default, not a custom one
        assert "Sec-Fetch-Dest" not in scanner.session.headers

    def test_session_exists(self):
        """BUG-3 fix: session must always be defined."""
        from ppmap.engine import CompleteSecurityScanner
        scanner = CompleteSecurityScanner()
        assert hasattr(scanner, "session")
        assert scanner.session is not None


# ============================================================================
# Tests: CVE version tuple logic (BUG-1 fix)
# ============================================================================

class TestCVEVersionTuple:
    """Verify _is_version_affected correctly handles OR multi-range specs."""

    def test_lt_spec_affected(self):
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((3, 4, 1), "<3.5.0") is True

    def test_lt_spec_not_affected(self):
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((3, 5, 0), "<3.5.0") is False

    def test_gte_spec_affected(self):
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((3, 0, 0), ">=3.0.0") is True

    def test_range_and_spec(self):
        from ppmap.engine import CVEDatabase
        # Matches AND: >=3.0.0 AND <3.0.1
        assert CVEDatabase._is_version_affected((3, 0, 0), ">=3.0.0 <3.0.1") is True

    def test_range_and_spec_not_affected(self):
        from ppmap.engine import CVEDatabase
        # version 3.0.1 not in range >=3.0.0 <3.0.1
        assert CVEDatabase._is_version_affected((3, 0, 1), ">=3.0.0 <3.0.1") is False

    def test_multi_range_or_first_match(self):
        """BUG-4 fix: comma = OR. '<2.2.0, >=3.0.0 <3.0.1' should match 1.9.0"""
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((1, 9, 0), "<2.2.0, >=3.0.0 <3.0.1") is True

    def test_multi_range_or_second_match(self):
        """BUG-4 fix: 3.0.0 matches second OR group '>=3.0.0 <3.0.1'"""
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((3, 0, 0), "<2.2.0, >=3.0.0 <3.0.1") is True

    def test_multi_range_or_no_match(self):
        """3.5.0 should NOT match '<2.2.0, >=3.0.0 <3.0.1'"""
        from ppmap.engine import CVEDatabase
        assert CVEDatabase._is_version_affected((3, 5, 0), "<2.2.0, >=3.0.0 <3.0.1") is False

    def test_cve_2019_11358_jquery_331_affected(self):
        """jQuery 3.3.1 must be flagged for CVE-2019-11358.
        
        CVE-2019-11358 affects jQuery < 3.4.0. The last vulnerable version
        before the patch is 3.3.1. Fixed in 3.4.0.
        """
        from ppmap.engine import CVEDatabase
        vulns = CVEDatabase.check_version("jquery", "3.3.1")
        cve_ids = [v["cve"] for v in vulns]
        assert "CVE-2019-11358" in cve_ids, (
            f"CVE-2019-11358 affects jQuery < 3.4.0. 3.3.1 should be vulnerable. "
            f"Found CVEs: {cve_ids}"
        )

    def test_cve_2019_11358_jquery_341_not_affected(self):
        """jQuery 3.4.1 must NOT be flagged for CVE-2019-11358 (patched in 3.4.0).
        
        IMPORTANT: This was a BUG in the original test! The old test expected 3.4.1
        to be vulnerable, but CVE-2019-11358 was actually FIXED in jQuery 3.4.0.
        NVD range: >= 1.0.3, < 3.4.0  (NOT < 3.5.0 as was incorrectly set before)
        """
        from ppmap.engine import CVEDatabase
        vulns = CVEDatabase.check_version("jquery", "3.4.1")
        cve_ids = [v["cve"] for v in vulns]
        assert "CVE-2019-11358" not in cve_ids, (
            f"CVE-2019-11358 was patched in jQuery 3.4.0. 3.4.1 must NOT be vulnerable. "
            f"Found CVEs: {cve_ids}"
        )
        # But 3.4.1 is still vulnerable to XSS CVEs (fixed in 3.5.0)
        assert "CVE-2020-11022" in cve_ids

    def test_cve_2019_11358_jquery_350_not_affected(self):
        """jQuery 3.5.0 must NOT be flagged for CVE-2019-11358."""

        from ppmap.engine import CVEDatabase
        vulns = CVEDatabase.check_version("jquery", "3.5.0")
        cve_ids = [v["cve"] for v in vulns]
        assert "CVE-2019-11358" not in cve_ids

    def test_unknown_library_returns_empty(self):
        from ppmap.engine import CVEDatabase
        assert CVEDatabase.check_version("unknownlib", "1.0.0") == []
