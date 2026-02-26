"""Configuration loader and defaults for PPMAP"""

import os
import logging

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "scanning": {
        "timeout": 15,
        "max_workers": 3,
        "max_retries": 2,
        "stealth_mode": False,
        "headless": True,
        "disable_ssl_verify": False,
    },
    "rate_limiting": {
        "enabled": False,
        "requests_per_minute": 60,
        "delay_between_requests": 0.5,
        "random_delay": True,
    },
    "testing": {
        "jquery_pp": True,
        "xss": True,
        "post_parameters": True,
        "server_side_pp": True,
        "waf_bypass": True,
        "confidence_scoring": True,
        "endpoint_discovery": True,
    },
    "reporting": {
        "format": ["json", "html"],
        "output_dir": "./reports",
        "include_poc": True,
        "template": "modern",
    },
    "logging": {"level": "INFO", "file_output": True, "console_output": True},
}


def _merge_dicts(base: dict, override: dict) -> dict:
    """Recursively merge override into base and return new dict."""
    result = {}
    for k in set(base.keys()).union(override.keys()):
        if (
            k in base
            and k in override
            and isinstance(base[k], dict)
            and isinstance(override[k], dict)
        ):
            result[k] = _merge_dicts(base[k], override[k])
        elif k in override:
            result[k] = override[k]
        else:
            result[k] = base[k]
    return result


def load(path: str = "config.yaml") -> dict:
    """Load YAML config if available, otherwise return defaults. Performs recursive merge."""
    try:
        import yaml

        if not os.path.exists(path):
            logger.debug("Config file not found, using DEFAULT_CONFIG")
            return DEFAULT_CONFIG.copy()

        with open(path, "r") as f:
            cfg = yaml.safe_load(f) or {}

        merged = _merge_dicts(DEFAULT_CONFIG, cfg)
        logger.info(f"Loaded configuration from {path}")
        return merged
    except ImportError:
        logger.warning("PyYAML not installed, using defaults")
        return DEFAULT_CONFIG.copy()
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()
