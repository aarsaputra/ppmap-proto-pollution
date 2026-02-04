"""Central logging setup for PPMAP"""
import sys
import logging
from pathlib import Path
from datetime import datetime


def setup_logging(log_level=logging.INFO, log_file=None):
    """Setup structured logging system and return root logger."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    detailed_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)-8s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter('[%(levelname)-8s] %(message)s')

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    file_handler = logging.FileHandler(log_dir / f"ppmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(file_handler)

    if log_file:
        custom_handler = logging.FileHandler(log_file)
        custom_handler.setLevel(logging.DEBUG)
        custom_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(custom_handler)

    return root_logger
