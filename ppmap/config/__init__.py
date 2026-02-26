import os
import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def load(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Optional path to config file. If None, looks for config.yaml
        
    Returns:
        Dictionary containing configuration
    """
    if not config_path:
        config_path = "config.yaml"
        
    if not os.path.exists(config_path):
        logger.debug(f"Config file {config_path} not found, using defaults")
        return {}
        
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        if not isinstance(config, dict):
            logger.warning(f"Invalid configuration format in {config_path}")
            return {}
            
        logger.debug(f"Loaded configuration from {config_path}")
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing config file {config_path}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error reading config file {config_path}: {e}")
        return {}
