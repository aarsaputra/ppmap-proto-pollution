from pathlib import Path
import json

from ppmap.reports import EnhancedReportGenerator


def test_generate_all_formats(tmp_path):
    outdir = tmp_path / 'reports'
    outdir.mkdir()
    rg = EnhancedReportGenerator(output_dir=str(outdir))

    findings = [
        {'type': 'jquery_pp', 'severity': 'HIGH', 'name': 'test1'},
        {'type': 'xss', 'severity': 'MEDIUM', 'name': 'test2'},
    ]

    generated = rg.generate_all_formats(findings, target='https://example.test', formats=['json', 'md', 'csv'])
    # verify keys
    assert 'json' in generated and generated['json']
    assert 'md' in generated and generated['md']
    assert 'csv' in generated and generated['csv']

    # files exist
    for p in generated.values():
        assert Path(p).exists()

    # basic content check for json
    with open(generated['json'], 'r') as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 2
