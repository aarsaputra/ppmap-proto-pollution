"""Unit test untuk modul reach_check (tanpa browser)."""
import pytest

from ppmap.scanner.reach_check import (
    build_instrumentation,
    build_reach_urls,
    make_canary,
    reach_verdict,
)


class TestCanary:
    def test_canary_prefix(self):
        c = make_canary("abc")
        assert c.startswith("ppmap_rc_")
        assert "abc" in c

    def test_canary_unique(self):
        import time as _t
        a = make_canary()
        _t.sleep(0.002)  # canary berbasis ms — pastikan beda tick
        b = make_canary()
        assert a != b


class TestInstrumentation:
    def test_contains_canary(self):
        js = build_instrumentation("ppmap_rc_xyz")
        assert "ppmap_rc_xyz" in js

    def test_hooks_jquery_sinks(self):
        js = build_instrumentation("ppmap_rc_xyz")
        for sink in ("jQuery.extend", "jQuery.parseJSON", "jQuery.fn.html",
                     "jQuery.init(selector)", "jQuery.init(HTML-string)"):
            assert sink in js

    def test_eval_and_innerhtml_hooks(self):
        js = build_instrumentation("ppmap_rc_xyz")
        assert "window.eval" in js
        assert "innerHTML" in js


class TestReachUrls:
    def test_eight_vectors(self):
        urls = build_reach_urls("https://t.example/p?id=1", "ppmap_rc_1")
        assert len(urls) == 8
        labels = {u["label"] for u in urls}
        assert {"hash_json", "query_bracket", "hash_html_canary", "query_html"} <= labels

    def test_full_navigation_distinct(self):
        # tiap vektor harus URL berbeda (full navigation, bukan fragment-doang)
        urls = build_reach_urls("https://t.example/p", "ppmap_rc_1")
        raw = [u["url"] for u in urls]
        assert len(set(raw)) == len(raw)

    def test_hash_last(self):
        urls = build_reach_urls("https://t.example/p", "ppmap_rc_1")
        for u in urls:
            if "#" in u["url"]:
                hash_part = u["url"].split("#", 1)[1]
                assert "_ppmap_rc=" not in hash_part  # param unik di query, bukan hash

    def test_canary_embedded(self):
        urls = build_reach_urls("https://t.example/p", "ppmap_rc_zz")
        assert all("ppmap_rc_zz" in u["url"] for u in urls)


class TestVerdict:
    def test_tier1_no_evidence(self):
        v = reach_verdict([], "c", False)
        assert v["verdict"] == "LIBRARY_VULNERABLE_ONLY" and v["tier"] == 1

    def test_tier2_canary_in_sink(self):
        hits = [{"sink": "jQuery.extend", "data": '{"c":1}'}]
        v = reach_verdict(hits, "c", False)
        assert v["verdict"] == "REACHABLE_FROM_URL" and v["tier"] == 2

    def test_tier3_execution(self):
        v = reach_verdict([], "c", True)
        assert v["verdict"] == "VERIFIED_EXECUTION" and v["tier"] == 3

    def test_tier_priority_exec_wins(self):
        hits = [{"sink": "s", "data": "c"}]
        v = reach_verdict(hits, "c", True)
        assert v["verdict"] == "VERIFIED_EXECUTION"
