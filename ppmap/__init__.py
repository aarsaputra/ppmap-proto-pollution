"""PPMAP package init - lightweight exports and versioning"""
__all__ = [
    "__version__",
    "FalsePositiveEngine",
    "get_fp_engine",
]

__version__ = "4.0.0"

# Lazy imports for core functionality
def get_fp_engine(*args, **kwargs):
    from .fp_engine import get_fp_engine as _get
    return _get(*args, **kwargs)
