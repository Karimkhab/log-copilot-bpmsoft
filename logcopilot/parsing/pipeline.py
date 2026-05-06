from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from ..domain import RawEvent
from .models import CanonicalEvent, ParseResult
from .parsers import (
    GenericFallbackParser,
    JsonParser,
    LogfmtParser,
    SyslogParser,
    TextMultilineParser,
    WebAccessParser,
    WindowsServicingParser,
)
from .registry import ParserRegistry

logger = logging.getLogger(__name__)


def discover_log_files(root: Path) -> list[Path]:
    """Находит подходящие файлы или ресурсы во входном пути. Область применения: лога, файлов.
    
    Args:
        root (Path): Корневой путь входных данных, относительно которого вычисляются имена файлов.
    
    Returns:
        list[Path]: Один входной файл или отсортированный список `.log` файлов, найденных внутри директории.
    """
    if root.is_file():
        return [root]
    return sorted(path for path in root.rglob("*.log") if path.is_file())


def build_default_registry() -> ParserRegistry:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        Нет параметров.
    
    Returns:
        ParserRegistry: Реестр стандартных парсеров в порядке приоритета, включая fallback-парсер.
    """
    registry = ParserRegistry()
    registry.register(JsonParser())
    registry.register(LogfmtParser())
    registry.register(WebAccessParser())
    registry.register(WindowsServicingParser())
    registry.register(SyslogParser())
    registry.register(TextMultilineParser())
    registry.register(GenericFallbackParser(), is_fallback=True)
    return registry


DEFAULT_REGISTRY = build_default_registry()


def canonical_to_raw_event(event: CanonicalEvent, source_file: str) -> RawEvent:
    """Выполняет вспомогательную операцию для события.
    
    Args:
        event (CanonicalEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        source_file (str): Имя файла-источника, которое попадет в событие и отчетные артефакты.
    
    Returns:
        RawEvent: Legacy-представление события с полями, перенесенными из CanonicalEvent.
    """
    return RawEvent(
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


def parse_file(path: Path, root: Path, registry: ParserRegistry | None = None) -> ParseResult:
    """Разбирает входные данные и преобразует их в структурированный результат. Область применения: файла.
    
    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        root (Path): Корневой путь входных данных, относительно которого вычисляются имена файлов.
        registry (ParserRegistry | None, optional): Реестр доступных парсеров, используемый для выбора подходящего обработчика.
    
    Returns:
        ParseResult: События выбранного парсера, статистика качества, предупреждения и сведения о fallback-разборе файла.
    """
    registry = registry or DEFAULT_REGISTRY # используем стандартный реестр, если другой не передали
    text = path.read_text(encoding="utf-8", errors="replace") # читаем файл с заменой битых символов
    source_file = path.name if root.is_file() else str(path.relative_to(root)) # имя файла для отчетов
    parser, selection = registry.select(text) # выбираем самый подходящий парсер по содержимому

    logger.info(
        "parser_selected: source_file=%s parser=%s detector_confidence=%.3f fallback=%s",
        source_file,
        selection.parser_name,
        selection.confidence,
        selection.used_fallback,
    )

    result = parser.parse(text, source=source_file) # парсим текст выбранным парсером

    logger.info(
        "parse_result: source_file=%s parser=%s events=%d confidence=%.3f warnings=%d",
        source_file,
        result.parser_name,
        len(result.events),
        result.confidence,
        len(result.warnings),
    )

    # Если парсер не проставил источник, добавляем его вручную.
    for event in result.events:
        if not event.source:
            event.source = source_file

    return result


def iter_canonical_events(root: Path, registry: ParserRegistry | None = None) -> Iterator[CanonicalEvent]:
    """Итерирует по входным данным и последовательно отдает подготовленные элементы. Область применения: событий.
    
    Args:
        root (Path): Корневой путь входных данных, относительно которого вычисляются имена файлов.
        registry (ParserRegistry | None, optional): Реестр доступных парсеров, используемый для выбора подходящего обработчика.
    
    Returns:
        Iterator[CanonicalEvent]: Ленивый поток канонических событий из всех найденных лог-файлов.
    """
    for path in discover_log_files(root):
        result = parse_file(path, root, registry=registry)
        yield from result.events


def iter_events_for_file(path: Path, root: Path, registry: ParserRegistry | None = None) -> Iterator[RawEvent]:
    """Итерирует по входным данным и последовательно отдает подготовленные элементы. Область применения: событий, файла.
    
    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        root (Path): Корневой путь входных данных, относительно которого вычисляются имена файлов.
        registry (ParserRegistry | None, optional): Реестр доступных парсеров, используемый для выбора подходящего обработчика.
    
    Returns:
        Iterator[RawEvent]: Ленивый поток legacy RawEvent для одного файла с корректной меткой source_file.
    """
    source_file = path.name if root.is_file() else str(path.relative_to(root))
    result = parse_file(path, root, registry=registry)
    for event in result.events:
        yield canonical_to_raw_event(event, source_file=source_file)


def iter_events(root: Path, registry: ParserRegistry | None = None) -> Iterator[RawEvent]:
    """Итерирует по входным данным и последовательно отдает подготовленные элементы. Область применения: событий.
    
    Args:
        root (Path): Корневой путь входных данных, относительно которого вычисляются имена файлов.
        registry (ParserRegistry | None, optional): Реестр доступных парсеров, используемый для выбора подходящего обработчика.
    
    Returns:
        Iterator[RawEvent]: Ленивый поток legacy RawEvent из всех `.log` файлов входного пути.
    """
    for path in discover_log_files(root):
        yield from iter_events_for_file(path, root, registry=registry)
