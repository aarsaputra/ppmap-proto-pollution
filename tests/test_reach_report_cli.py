"""Test AUDIT-19c: report.html hasil jalur CLI (`--scan`) juga wajib menampilkan
verdict reachability.

Latar: AUDIT-19 memasang badge/banner di `ppmap/reports/html_report.py`, tetapi
`--scan` menulis report.html lewat `EnhancedReportGenerator.generate_html_report`
(ppmap/reports/generator.py) yang punya template sendiri. Akibatnya badge tetap
hilang di laporan yang benar-benar dihasilkan pengguna, dan temuan
LIBRARY_VULNERABLE_ONLY tampil setara dengan temuan yang jalurnya terbukti.

Test ini mengunci jalur generator (CLI), bukan hanya jalur html_report.
"""
from ppmap.reports.generator import EnhancedReportGenerator


def _f(**meta):
    base = {
        "type": "jquery_pp",
        "severity": "HIGH",
        "name": "Finding",
        "payload": "x",
        "confidence": 0.9,
        "verified": False,
    }
    base.update(meta)
    return base


def _render(tmp_path, findings, target="http://lab.local"):
    gen = EnhancedReportGenerator(str(tmp_path))
    out = gen.generate_all_formats(findings, target, formats=["html"])
    assert "html" in out, "report html tidak dihasilkan"
    with open(out["html"]) as fh:
        return fh.read()


def test_cli_generator_shows_reach_badges(tmp_path):
    html = _render(
        tmp_path,
        [
            _f(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1),
            _f(type="dom_xss", severity="CRITICAL", verified=True,
               reach_verdict="VERIFIED_EXECUTION", reach_tier=3),
        ],
    )
    assert "LIBRARY-ONLY (tier 1)" in html
    assert "EXECUTED (tier 3)" in html
    assert "Reachability (reach-check)" in html


def test_cli_generator_banner_counts_all_verdicts(tmp_path):
    html = _render(
        tmp_path,
        [
            _f(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1),
            _f(type="xss", reach_verdict="REACHABLE_FROM_URL", reach_tier=2),
        ],
    )
    assert "LIBRARY_VULNERABLE_ONLY ×1" in html
    assert "REACHABLE_FROM_URL ×1" in html


def test_cli_generator_without_reach_metadata_has_no_banner(tmp_path):
    html = _render(tmp_path, [_f()])
    assert "Reachability (reach-check)" not in html
    assert "LIBRARY-ONLY" not in html


def test_cli_generator_library_only_never_labelled_executed(tmp_path):
    """Regresi presentasi: temuan library-only tidak boleh tampil EXECUTED.

    Legend/banner menyebut kata EXECUTED sebagai penjelasan, jadi yang diperiksa
    adalah badge per-finding: elemen badge finding tidak boleh berisi EXECUTED.
    """
    html = _render(tmp_path, [_f(reach_verdict="LIBRARY_VULNERABLE_ONLY", reach_tier=1)])
    # Badge finding = span method-label berisi label tier. Legend/banner juga
    # memuat frasa "LIBRARY-ONLY (tier 1)" sebagai penjelasan, jadi diffilter.
    badges = [
        c for c in html.split("<")
        if "method-label" in c and "LIBRARY-ONLY (tier 1)" in c
    ]
    assert badges, "badge LIBRARY-ONLY tidak dirender"
    for chunk in badges:
        assert "EXECUTED" not in chunk, f"badge library-only dilabeli executed: {chunk[:150]}"
    # tidak boleh ada badge EXECUTED sama sekali (tidak ada finding tier 3)
    assert ">EXECUTED (tier 3)<" not in html
