from __future__ import annotations

"""Публичный API пакета LogCopilot."""

__all__ = ["__version__", "PipelineConfig", "RunResult", "run_pipeline"]

__version__ = "0.1.0"


def __getattr__(name: str):
    """Лениво возвращает публичный атрибут модуля, сохраняя совместимость импортов.
    
    Args:
        name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
    
    Returns:
        Any: Публичный объект пакета, загруженный лениво по имени, например функция запуска конвейера или доменная модель.
    
    Raises:
        AttributeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if name == "run_pipeline":
        from .pipeline import run_pipeline

        return run_pipeline
    if name in {"PipelineConfig", "RunResult"}:
        from .domain import PipelineConfig, RunResult

        return {"PipelineConfig": PipelineConfig, "RunResult": RunResult}[name]
    raise AttributeError(f"module 'logcopilot' has no attribute {name!r}")
