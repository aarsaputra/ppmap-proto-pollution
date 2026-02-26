import os
import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def load(path: str = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        path: Optional path to config file. If None, looks for config.yaml
        
    Returns:
        Dictionary containing configuration
    """
    from ppmap.config.settings import CONFIG
    import copy
    default_config = copy.deepcopy(CONFIG)
    
    if not path:
        path = "config.yaml"
        
    if not os.path.exists(path):
        logger.debug(f"Config file {path} not found, using defaults")
        return default_config
        
    try:
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
            
        if not isinstance(config, dict):
            logger.warning(f"Invalid configuration format in {path}")
            return default_config
            
        logger.debug(f"Loaded configuration from {path}")
        
        # Deep merge with defaults
        def merge_dicts(d1, d2):
            for k, v in d2.items():
                if isinstance(v, dict) and k in d1 and isinstance(d1[k], dict):
                    merge_dicts(d1[k], v)
                else:
                    d1[k] = v
            return d1
            
        return merge_dicts(default_config, config)
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing config file {path}: {e}")
        return default_config
    except Exception as e:
        logger.error(f"Error reading config file {path}: {e}")
        return default_config
