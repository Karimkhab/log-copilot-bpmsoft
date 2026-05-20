from __future__ import annotations

"""Точка входа этапа конвейера для построения канонических событий."""

import logging
import time
from typing import Dict

from ..domain import EventBuildStageResult, PipelineContext
from .events import build_event_from_canonical

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


def run_event_building(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: события.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_event_building`.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if context.parse_result is None:
        raise RuntimeError("Parsing must run before event building.")

    build_started = time.perf_counter()
    events = []
    multiline_merges = 0
    _print_phase(f"event building started: records={len(context.parsed_records)}")
    for parsed_record in context.parsed_records:
        event = build_event_from_canonical(
            parsed_record.event,
            source_file=parsed_record.source_file,
            run_id=context.run_id,
            normalization_stats=context.normalization_stats,
        )
        events.append(event)
        if event.line_count > 1:
            multiline_merges += 1

    timings: Dict[str, float] = {"event_building": time.perf_counter() - build_started}
    _print_phase(
        f"event building finished: events={len(events)} "
        f"duration={timings['event_building']:.3f}s"
    )
    context.events = events
    context.event_build_result = EventBuildStageResult(
        events=events,
        event_count=len(events),
        multiline_merges=multiline_merges,
        timings=timings,
    )
    context.timings.update(timings)
    return context
