from __future__ import annotations

"""Точка входа этапа конвейера для обработки логов только парсингом."""

import logging
import time
from pathlib import Path
from typing import Dict

from ..domain import ParseFileDiagnostics, ParsedLogRecord, ParseStageResult, PipelineContext
from .pipeline import discover_log_files, parse_file

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


def _source_file_label(path: Path, input_path_obj: Path) -> str:
    """Выполняет вспомогательную операцию для файла.
    
    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        input_path_obj (Path): Значение `input_path_obj`, используемое функцией при выполнении операции.
    
    Returns:
        str: Имя файла для логов и отчетов: basename для одиночного файла или относительный путь внутри директории.
    """
    if input_path_obj.is_file():
        return path.name
    return str(path.relative_to(input_path_obj))


def _parse_result_payload(source_file: str, parse_result) -> ParseFileDiagnostics:
    """Разбирает внутренний фрагмент данных и возвращает структурированное представление. Область применения: полезной нагрузки.
    
    Args:
        source_file (str): Имя файла-источника, которое попадет в событие и отчетные артефакты.
        parse_result (Any): Результат выполнения конвейера или промежуточного этапа, из которого берутся данные.
    
    Returns:
        ParseFileDiagnostics: Диагностика парсинга одного файла с именем парсера, уверенностью, статистикой и предупреждениями.
    """
    return ParseFileDiagnostics(
        source_file=source_file,
        parser_name=parse_result.parser_name,
        confidence=parse_result.confidence,
        stats=dict(parse_result.stats),
        warnings=list(parse_result.warnings),
    )


def run_parsing(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_parsing`.
    """
    input_path_obj = context.input_path
    source_files = discover_log_files(input_path_obj) # файлы, которые нужно распарсить
    parsed_records: list[ParsedLogRecord] = []        # общий список событий из всех файлов
    file_results: list[ParseFileDiagnostics] = []     # диагностика парсинга по файлам
    timings: Dict[str, float] = {}                    # замеры времени для этого шага

    parse_started = time.perf_counter()
    _print_phase(f"parse started: profile={context.config.profile} input={input_path_obj.name}")
    for path in source_files:
        source_file = _source_file_label(path, input_path_obj)  # имя файла для логов и отчетов
        logger.debug("parse_file_started: run_id=%s source_file=%s", context.run_id, source_file)

        parse_result = parse_file(path, input_path_obj)  # результат парсинга одного файла
        file_results.append(_parse_result_payload(source_file, parse_result))

        _print_phase(
            f"parsed {source_file}: parser={parse_result.parser_name} "
            f"confidence={parse_result.confidence:.2f} events={len(parse_result.events)}"
        )

        if parse_result.warnings:
            logger.info(
                "parse_warnings: run_id=%s source_file=%s warnings=%d",
                context.run_id,
                source_file,
                len(parse_result.warnings),
            )

        for canonical_event in parse_result.events:
            parsed_records.append(ParsedLogRecord(source_file=source_file, event=canonical_event))

    timings["parse"] = time.perf_counter() - parse_started

    _print_phase(
        f"parse finished: files={len(source_files)} events={len(parsed_records)} "
        f"parse_time={timings['parse']:.3f}s"
    )

    context.parsed_records = parsed_records
    context.parse_result = ParseStageResult(
        parsed_records=parsed_records,
        file_results=file_results,
        event_count=len(parsed_records),
        source_files=source_files,
        timings=timings,
    )
    context.timings.update(timings)
    return context
