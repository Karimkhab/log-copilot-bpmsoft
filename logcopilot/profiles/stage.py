from __future__ import annotations

"""Точка входа этапа конвейера для вычисления профиля."""

import logging
import time

from ..domain import PipelineContext, ProfileStageResult
from .heatmap import run_heatmap_profile
from .incidents import run_incidents_profile
from .traffic import run_traffic_profile

logger = logging.getLogger(__name__)


def _print_phase(message: str) -> None:
    """Выполняет вспомогательную операцию для логики проекта.

    Args:
        message (str): Значение `message`, используемое функцией при выполнении операции.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    logger.info("run_phase: %s", message)
    print(f"[logcopilot] {message}")


def run_profile_computation(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: профиля.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_profile_computation`.
    
    Raises:
        ValueError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    profile = context.config.profile
    events = context.events
    profile_started = time.perf_counter()
    _print_phase(f"profile compute started: profile={profile} events={len(events)}")

    if profile == "incidents":
        profile_result = run_incidents_profile(
            events,
            context.run_dir,
            source_name=context.input_path.name,
            semantic=context.config.semantic,
            semantic_model=context.config.semantic_model,
            semantic_min_cluster_size=context.config.semantic_min_cluster_size,
            semantic_min_samples=context.config.semantic_min_samples,
            semantic_cache_dir=context.base_output_dir / ".semantic_cache",
            semantic_max_signatures=2500,
            progress_callback=lambda message: _print_phase(message),
        )
    elif profile == "heatmap":
        profile_result = run_heatmap_profile(events, context.run_dir)
    elif profile == "traffic":
        profile_result = run_traffic_profile(events, context.run_dir)
    else:
        raise ValueError(f"Unsupported profile: {profile}")

    duration = time.perf_counter() - profile_started
    _print_phase(f"profile compute finished: profile={profile} duration={duration:.3f}s")
    context.profile_result = ProfileStageResult(
        profile=profile,
        payload=profile_result,
        duration_seconds=duration,
    )
    context.timings["profile_compute"] = duration
    return context
