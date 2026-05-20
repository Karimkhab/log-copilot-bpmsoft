from __future__ import annotations

"""Compatibility package for the historical `logcopilot` import path.

The implementation package was moved to `src`, but external scripts may still
import `logcopilot.*`. Reusing `src.__path__` keeps those imports working
without duplicating source files.
"""

from importlib import import_module
from typing import Any

_src = import_module("src")

__path__ = _src.__path__
__all__ = getattr(_src, "__all__", [])
__version__ = getattr(_src, "__version__", "0.1.0")


def __getattr__(name: str) -> Any:
    return getattr(_src, name)
