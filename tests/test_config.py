import os
import tempfile
import yaml

from ppmap import config as cfg


def test_load_defaults_without_yaml():
    # Ensure load() returns a dict and contains scanning.disable_ssl_verify
    c = cfg.load(path='nonexistent_config_hopefully_missing.yaml')
    assert isinstance(c, dict)
    assert 'scanning' in c
    assert 'disable_ssl_verify' in c['scanning'] or 'disable_ssl_verify' in c['scanning']


def test_load_merge_with_yaml(tmp_path):
    # Create a small YAML override and ensure merge applies
    override = {
        'scanning': {
            'timeout': 3,
            'disable_ssl_verify': True
        },
        'reporting': {
            'output_dir': './myreports'
        }
    }
    p = tmp_path / 'temp_config.yaml'
    p.write_text(yaml.dump(override))

    c = cfg.load(path=str(p))
    assert c['scanning']['timeout'] == 3
    assert c['scanning']['disable_ssl_verify'] is True
    assert c['reporting']['output_dir'] == './myreports'
