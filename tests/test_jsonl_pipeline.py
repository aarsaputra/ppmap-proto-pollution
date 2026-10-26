"""
Tests: output pipeline-friendly PPMAP (JSON satu-objek-per-baris saat pipeline).

Konteks lapangan: `subfinder | ppmap.py --scan --stdin` dipakai di pipeline.
Bila report JSON di-pretty-print (indent=2), satu target memecah jadi puluhan
baris sehingga `jq -c .` / `grep` per-baris rusak.

Kontrak yang dikunci di sini:
  1. `--stdin` => EnhancedReportGenerator(pipeline_mode=True)
  2. pipeline_mode  => file .json berisi 1 objek per baris (JSONL valid)
  3. non-pipeline   => file .json tetap satu array ter-indentasi (perilaku lama)

Test ini menjalankan generator sungguhan ke tmp_path (tanpa jaringan/scan),
jadi cepat & deterministik.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ppmap.reports.generator import EnhancedReportGenerator  # noqa: E402

FINDINGS = [
    {"url": "http://127.0.0.1:8903/gadget?__proto__[x]=1", "vuln_type": "proto_pollution",
     "severity": "high", "poi": ["x"]},
    {"url": "http://127.0.0.1:8903/purify#__proto__[y]=2", "vuln_type": "proto_pollution",
     "severity": "medium", "poi": ["y"]},
]


def _json_report(tmp_path, pipeline_mode):
    gen = EnhancedReportGenerator(str(tmp_path), pipeline_mode=pipeline_mode)
    generated = gen.generate_all_formats(
        findings=[dict(f) for f in FINDINGS],
        target="127.0.0.1",
        formats=["json"],
    )
    assert "json" in generated, "laporan JSON tidak dihasilkan"
    with open(generated["json"], "r", encoding="utf-8") as fh:
        return fh.read()


def test_pipeline_mode_is_one_object_per_line(tmp_path):
    raw = _json_report(tmp_path, pipeline_mode=True)
    lines = [ln for ln in raw.splitlines() if ln.strip()]

    assert len(lines) == len(FINDINGS), (
        f"pipeline mode harus 1 baris per finding, dapat {len(lines)} baris"
    )
    # Tiap baris harus JSON mandiri & memuat url yang benar
    urls = []
    for ln in lines:
        obj = json.loads(ln)  # gagal -> bukan JSONL valid
        urls.append(obj["url"])
    assert urls == [f["url"] for f in FINDINGS]


def test_non_pipeline_keeps_single_indented_array(tmp_path):
    raw = _json_report(tmp_path, pipeline_mode=False)
    parsed = json.loads(raw)

    assert isinstance(parsed, list), "non-pipeline harus tetap satu array JSON"
    assert len(parsed) == len(FINDINGS)
    # Pretty-print (indent=2) -> file lebih dari satu baris
    assert len(raw.splitlines()) > 1


def test_pipeline_mode_default_is_off(tmp_path):
    gen = EnhancedReportGenerator(str(tmp_path))
    assert gen.pipeline_mode is False, (
        "default pipeline_mode harus False (output manusia tetap pretty-print)"
    )


def test_pipeline_flag_wired_from_stdin_in_cli():
    """--stdin harus menyalakan pipeline_mode di ppmap.py."""
    with open(os.path.join(ROOT, "ppmap.py"), "r", encoding="utf-8") as fh:
        src = fh.read()
    assert 'pipeline_mode = bool(getattr(args, "stdin", False))' in src, (
        "ppmap.py harus menurunkan pipeline_mode dari flag --stdin"
    )
    assert src.count("pipeline_mode=pipeline_mode") == 2, (
        "jalur async & sinkron dua-duanya harus meneruskan pipeline_mode"
    )
