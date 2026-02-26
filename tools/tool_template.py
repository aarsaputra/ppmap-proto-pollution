#!/usr/bin/env python3
"""
PPMAP Tool Template - Use this as a boilerplate for new tools

Provides common patterns and security best practices:
- Logging setup
- Input validation
- Error handling
- Safe file operations
- Path traversal protection
"""

import os
import sys
import json
import logging
from pathlib import Path
from argparse import ArgumentParser
from typing import Optional, Dict, List, Any

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the tool.
    
    Args:
        verbose: Enable debug logging
        
    Returns:
        Configured logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ppmap_tools.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)


logger = setup_logging()


# ============================================================================
# PATH SECURITY & VALIDATION
# ============================================================================

def validate_file_path(filepath: str, allowed_dir: str = None, must_exist: bool = True) -> Optional[Path]:
    """
    Validate file path to prevent directory traversal attacks.
    
    Args:
        filepath: Path to validate
        allowed_dir: Parent directory to restrict access (prevents ../../etc/passwd)
        must_exist: Require file to exist
        
    Returns:
        Validated absolute path or None if invalid
        
    Example:
        # Only allow files within ./report/
        path = validate_file_path(user_input, allowed_dir="./report")
        if not path:
            logger.error("Security: Invalid file path")
            return
    """
    if allowed_dir is None:
        allowed_dir = os.getcwd()
    
    try:
        # Resolve to absolute paths to prevent traversal bypass
        file_path = Path(filepath).resolve()
        allowed_path = Path(allowed_dir).resolve()
        
        # SECURITY CHECK: Ensure file is within allowed directory
        try:
            file_path.relative_to(allowed_path)
        except ValueError:
            logger.error(f"🔴 SECURITY: Path traversal attempt detected!")
            logger.error(f"   Attempted: {file_path}")
            logger.error(f"   Allowed:   {allowed_path}")
            return None
        
        # Check existence if required
        if must_exist and not file_path.exists():
            logger.error(f"File not found: {filepath}")
            return None
        
        if must_exist and not file_path.is_file():
            logger.error(f"Not a file: {filepath}")
            return None
        
        logger.debug(f"✅ Validated path: {file_path}")
        return file_path
    
    except Exception as e:
        logger.error(f"Error validating path '{filepath}': {e}")
        return None


def validate_directory(dirpath: str, must_exist: bool = True) -> Optional[Path]:
    """
    Validate directory path.
    
    Args:
        dirpath: Path to validate
        must_exist: Require directory to exist
        
    Returns:
        Validated absolute path or None if invalid
    """
    try:
        path = Path(dirpath).resolve()
        
        if must_exist and not path.exists():
            logger.error(f"Directory not found: {dirpath}")
            return None
        
        if must_exist and not path.is_dir():
            logger.error(f"Not a directory: {dirpath}")
            return None
        
        logger.debug(f"✅ Validated directory: {path}")
        return path
    except Exception as e:
        logger.error(f"Error validating directory '{dirpath}': {e}")
        return None


# ============================================================================
# JSON FILE OPERATIONS
# ============================================================================

def load_json_file(filepath: str) -> Optional[Dict]:
    """
    Load JSON file safely.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Parsed JSON data or None if error
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.debug(f"Loaded JSON from {filepath}")
        return data
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filepath}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}", exc_info=True)
        return None


def save_json_file(filepath: str, data: Dict, indent: int = 2) -> bool:
    """
    Save JSON file safely.
    
    Args:
        filepath: Path where to save
        data: Data to serialize
        indent: JSON indentation (default: 2)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        logger.info(f"Saved to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving {filepath}: {e}")
        return False


# ============================================================================
# TEXT PROCESSING & ESCAPING
# ============================================================================

def escape_markdown(text: str) -> str:
    """
    Escape special markdown characters to prevent injection.
    
    Args:
        text: Text to escape
        
    Returns:
        Escaped text safe for markdown
        
    Example:
        payload = "test*payload`with[special]_chars"
        safe = escape_markdown(payload)
        # Result: "test\\*payload\\`with\\[special\\]\\_chars"
    """
    if not text:
        return "N/A"
    
    text = str(text)
    
    # Escape markdown special characters
    special_chars = {
        '`': '\\`',
        '*': '\\*',
        '_': '\\_',
        '[': '\\[',
        ']': '\\]',
        '#': '\\#',
        '!': '\\!',
        '\\': '\\\\',
    }
    
    for char, escaped in special_chars.items():
        text = text.replace(char, escaped)
    
    return text


def escape_csv(text: str) -> str:
    """
    Escape text for CSV format.
    
    Args:
        text: Text to escape
        
    Returns:
        Escaped text safe for CSV
    """
    if not text:
        return ""
    
    text = str(text)
    
    # If contains comma, quote, or newline - wrap in quotes and escape
    if any(c in text for c in [',', '"', '\n', '\r']):
        text = '"' + text.replace('"', '""') + '"'
    
    return text


# ============================================================================
# MAIN TEMPLATE
# ============================================================================

def main():
    """Main entry point - customize for your tool"""
    parser = ArgumentParser(description="PPMAP Tool Template")
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose (debug) logging'
    )
    parser.add_argument(
        '--config',
        default=os.getenv('PPMAP_CONFIG', './config.json'),
        help='Configuration file (default: ./config.json or PPMAP_CONFIG env var)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info("Tool started successfully")
    logger.info(f"Configuration file: {args.config}")
    
    # Validate config file exists
    config_path = validate_file_path(args.config, must_exist=False)
    if config_path and config_path.exists():
        config = load_json_file(str(config_path))
        if config:
            logger.info(f"Loaded configuration with {len(config)} keys")
    else:
        logger.warning(f"Configuration file not found: {args.config}")
    
    # TODO: Implement actual tool logic here
    logger.info("Tool execution completed")


if __name__ == "__main__":
    main()
