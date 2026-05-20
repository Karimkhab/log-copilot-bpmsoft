from __future__ import annotations

"""Публичный API пакета LogCopilot."""

from .domain import PipelineConfig, RunResult
from .pipeline import run_batch_pipeline, run_pipeline

__all__ = [
    "__version__",
    "PipelineConfig",
    "RunResult",
    "run_batch_pipeline",
    "run_pipeline",
]

__version__ = "0.1.0"
