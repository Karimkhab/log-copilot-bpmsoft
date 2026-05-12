from __future__ import annotations

"""LogCopilot public package API."""

__all__ = ["__version__", "PipelineConfig", "RunResult", "run_batch_pipeline", "run_pipeline"]

__version__ = "0.1.0"


def __getattr__(name: str):
    """Load public API objects lazily to keep module execution clean."""
    if name == "run_pipeline":
        from .pipeline import run_pipeline

        return run_pipeline
    if name == "run_batch_pipeline":
        from .pipeline import run_batch_pipeline

        return run_batch_pipeline
    if name in {"PipelineConfig", "RunResult"}:
        from .domain import PipelineConfig, RunResult

        return {"PipelineConfig": PipelineConfig, "RunResult": RunResult}[name]
    raise AttributeError(f"module 'logcopilot' has no attribute {name!r}")
