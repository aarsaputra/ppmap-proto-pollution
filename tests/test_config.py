import yaml

from ppmap import config as cfg


def test_load_defaults_without_yaml():
    # Ensure load() returns a dict and contains default keys from settings.CONFIG
    c = cfg.load(path='nonexistent_config_hopefully_missing.yaml')
    assert isinstance(c, dict)
    assert 'timeout' in c
    assert c['timeout'] == 15


def test_load_merge_with_yaml(tmp_path):
    # Create a small YAML override and ensure merge applies
    override = {
        'timeout': 5,
        'new_custom_key': 'test_value'
    }
    p = tmp_path / 'temp_config.yaml'
    p.write_text(yaml.dump(override))

    c = cfg.load(path=str(p))
    assert c['timeout'] == 5
    assert c['new_custom_key'] == 'test_value'
