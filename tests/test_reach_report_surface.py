"""Test AUDIT-19: verdict reachability wajib tampil di laporan HTML.

Latar: `--scan` sudah meng-enrich finding dengan metadata reach_verdict/reach_tier
(AUDIT-18), tetapi report.json (via Finding.to_dict) dan report.html dulu tidak
menampilkan apa pun. Akibatnya temuan LIBRARY_VULNERABLE_ONLY (versi rentan saja)
tampil setara dengan temuan yang jalurnya terbukti — false positive by presentation.

Test ini mengunci: badge + banner reach muncul, dan LIBRARY-ONLY tidak pernah
tampil sebagai EXECUTED.
"""
from ppmap.reports.html_report import (
    generate_html_report,
    _reach_badge,
    _reach_banner,
)


def _finding(vtype="jquery_pp", **meta):
    f = {
        "type": vtype,
        "severity": "HIGH",
        "name": f"Finding {vtype}",
        "payload": "x",
        "confidence": 0.9,
        "verified": False,
    }
    f.update(meta)
    return f


def test_badge_render_for_scannable_verdicts():
    assert "REACHABLE (tier 2)" in _reach_badge(
        {"reach_verdict": "REACHABLE_FROM_URL", "reach_tier": 2}
    )
    assert "EXECUTED (tier 3)" in _reach_badge(
        {"reach_verdict": "VERIFIED_EXECUTION", "reach_tier": 3}
    )
    assert "LIBRARY-ONLY (tier 1)" in _reach_badge(
        {"reach_verdict": "LIBRARY_VULNERABLE_ONLY", "reach_tier": 1}
    )


def test_badge_absent_without_verdict():
    assert _reach_badge({"type": "xss"}) == ""


def test_badge_escapes_unknown_verdict():
    badge = _reach_badge({"reach_verdict": "<script>alert(1)</script>"})
    assert "<script>" not in badge
    assert "&lt;script&gt;" in badge


def test_badge_unknown_tier_is_none_marker():
    badge = _reach_badge({"reach_verdict": "UNAVAILABLE", "reach_tier": None})
    assert "REACH N/A" in badge
    assert "tier" not in badge


def test_banner_empty_when_no_verdict():
    assert _reach_banner([_finding(), _finding("xss")]) == ""


def test_banner_counts_each_verdict():
    findings = [
        _finding(reach_verdict="REACHABLE_FROM_URL", reach_tier=2),
        _finding(reach_verdict="REACHABLE_FROM_URL", reach_tier=2),
        _finding(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1),
    ]
    banner = _reach_banner(findings)
    assert "REACHABLE_FROM_URL ×2" in banner
    assert "LIBRARY_VULNERABLE_ONLY ×1" in banner
    # warna dominan = verdict terbanyak (REACHABLE -> #e65100, bukan EXECUTED merah)
    assert "#e65100" in banner


def test_banner_tie_is_deterministic():
    a = _reach_banner([
        _finding(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1),
        _finding(reach_verdict="REACHABLE_FROM_URL", reach_tier=2),
    ])
    b = _reach_banner([
        _finding(reach_verdict="REACHABLE_FROM_URL", reach_tier=2),
        _finding(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1),
    ])
    assert a == b  # urutan input tidak mengubah warna/isi banner


def test_html_report_contains_badge_and_banner():
    pp = _finding("jquery_pp", name="PP-1", reach_verdict="REACHABLE_FROM_URL", reach_tier=2)
    xss = _finding("xss", name="XSS-1", param="q",
                   reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1)
    html = generate_html_report("http://127.0.0.1:8903/gadget", [pp, xss], [pp], [xss])
    assert "Reachability (reach-check)" in html
    assert "REACHABLE (tier 2)" in html
    assert "LIBRARY-ONLY (tier 1)" in html
    # LIBRARY-ONLY tidak boleh dipromosikan jadi EXECUTED (badge-nya, bukan teks legenda)
    assert '>EXECUTED (tier 3) · tier' not in html
    assert '>LIBRARY-ONLY (tier 1) · tier 1</span>' in html


def test_reach_block_uses_reason_when_present():
    from ppmap.reports.html_report import _reach_block
    blk = _reach_block({
        "reach_verdict": "LIBRARY_VULNERABLE_ONLY",
        "reach_tier": 1,
        "reach_reason": "jquery 1.12.4 < 3.5.0 pada <script src>",
    })
    assert "LIBRARY-ONLY (tier 1)" in blk
    assert "Bukti:" in blk
    assert "jquery 1.12.4" in blk


def test_reach_block_default_reason_for_library_only():
    from ppmap.reports.html_report import _reach_block
    blk = _reach_block({"reach_verdict": "LIBRARY_VULNERABLE_ONLY", "reach_tier": 1})
    assert "jalur serangan dari URL target tidak terbukti" in blk


def test_reach_block_no_verdict_is_empty():
    from ppmap.reports.html_report import _reach_block
    assert _reach_block({"name": "x"}) == ""


def test_html_uses_reach_block_not_bare_badge():
    from ppmap.reports.html_report import generate_html_report
    pp = _finding("jquery_pp", name="PP-1", reach_verdict="LIBRARY_VULNERABLE_ONLY",
                  reach_tier=1)
    xss = _finding("xss", name="XSS-1", param="q",
                   reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1)
    html = generate_html_report("http://127.0.0.1:8903/gadget", [pp], [pp], [xss])
    assert html.count("Bukti:") >= 2  # PP section + XSS section
