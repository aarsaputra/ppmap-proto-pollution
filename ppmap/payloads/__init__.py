"""
ppmap/payloads/__init__.py
Re-exports from flat payloads.py for backward compat + new sub-modules.
"""

# Re-export from legacy flat payloads.py
from ppmap.payloads.base import (
    QUICK_POC_PAYLOADS,
    XSS_PAYLOADS,
    DEFAULT_XSS_PARAMS,
    SSPP_PAYLOADS,
    RCE_PAYLOADS,
    MUTATION_VECTORS,
)

# New namespaced sub-module exports
from ppmap.payloads.gadgets import GADGET_PROPERTIES

__all__ = [
    "QUICK_POC_PAYLOADS",
    "XSS_PAYLOADS",
    "DEFAULT_XSS_PARAMS",
    "SSPP_PAYLOADS",
    "RCE_PAYLOADS",
    "MUTATION_VECTORS",
    "GADGET_PROPERTIES",
]
