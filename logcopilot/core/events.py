from __future__ import annotations

"""Построитель канонических событий, общий для парсинга и выполнения профилей."""

import uuid
from typing import Optional

from ..domain import Event, RawEvent
from ..parsing.models import CanonicalEvent
from ..text import (
    NormalizationStats,
    build_embedding_text,
    build_signature,
    make_event_signature,
)


def _build_event_from_raw_like(
    raw_event: RawEvent,
    run_id: str,
    normalization_stats: Optional[NormalizationStats] = None,
) -> Event:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: события.
    
    Args:
        raw_event (RawEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        normalization_stats (Optional[NormalizationStats], optional): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        Event: Обогащенное каноническое событие с нормализованным сообщением, сигнатурой, признаками инцидента и идентификатором.
    """
    normalized_message, exception_type, stack_frames, is_incident = make_event_signature(
        raw_event,
        normalization_stats=normalization_stats,
    )
    event = Event(
        event_id=str(uuid.uuid4()),
        run_id=run_id,
        source_file=raw_event.source_file,
        parser_profile=raw_event.parser_profile,
        parser_confidence=raw_event.parser_confidence,
        timestamp=raw_event.timestamp,
        level=raw_event.level,
        message=raw_event.message,
        stacktrace=raw_event.stacktrace,
        raw_text=raw_event.raw_text,
        line_count=raw_event.line_count,
        normalized_message=normalized_message,
        signature_hash=build_signature(
            normalized_message,
            exception_type,
            stack_frames,
        ),
        embedding_text="",
        exception_type=exception_type,
        stack_frames=stack_frames,
        component=raw_event.component,
        request_id=raw_event.request_id,
        trace_id=raw_event.trace_id,
        http_status=raw_event.http_status,
        method=raw_event.method,
        path=raw_event.path,
        latency_ms=raw_event.latency_ms,
        response_size=raw_event.response_size,
        client_ip=raw_event.client_ip,
        user_agent=raw_event.user_agent,
        attributes=dict(raw_event.attributes),
        is_incident=is_incident,
    )
    event.embedding_text = build_embedding_text(event)
    return event


def build_event(
    raw_event: RawEvent,
    run_id: str,
    normalization_stats: Optional[NormalizationStats] = None,
) -> Event:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: события.
    
    Args:
        raw_event (RawEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        normalization_stats (Optional[NormalizationStats], optional): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        Event: Каноническое событие, построенное из RawEvent и готовое для профилей, отчетов и сохранения.
    """
    return _build_event_from_raw_like(
        raw_event,
        run_id=run_id,
        normalization_stats=normalization_stats,
    )


def build_event_from_canonical(
    event: CanonicalEvent,
    source_file: str,
    run_id: str,
    normalization_stats: Optional[NormalizationStats] = None,
) -> Event:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: события.
    
    Args:
        event (CanonicalEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        source_file (str): Имя файла-источника, которое попадет в событие и отчетные артефакты.
        run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        normalization_stats (Optional[NormalizationStats], optional): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        Event: Каноническое событие доменного слоя, построенное напрямую из CanonicalEvent парсера.
    """
    raw_event = RawEvent(
        source_file=source_file,
        parser_profile=event.parser_name,
        parser_confidence=event.parser_confidence,
        timestamp=event.timestamp,
        level=event.level,
        message=event.message,
        stacktrace=event.stacktrace,
        raw_text=event.raw_text,
        line_count=event.line_count,
        component=event.component,
        request_id=event.request_id,
        trace_id=event.trace_id,
        http_status=event.http_status,
        method=event.http_method,
        path=event.http_path,
        latency_ms=event.latency_ms,
        response_size=event.response_size,
        client_ip=event.client_ip,
        user_agent=event.user_agent,
        attributes=dict(event.attributes),
    )
    return _build_event_from_raw_like(
        raw_event,
        run_id=run_id,
        normalization_stats=normalization_stats,
    )
