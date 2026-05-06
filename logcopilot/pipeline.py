from __future__ import annotations

"""Публичная точка входа оркестрации конвейера LogCopilot."""

from collections import Counter
from dataclasses import asdict
import logging
from pathlib import Path
from typing import Dict, List, Optional

from .analysis import AnalysisQualityAccumulator
from .analysis.quality import assess_profile_fit
from .analysis.validation import run_quality_validation
from .agent import run_agent_pipeline
from .core import run_event_building
from .domain import (
    AnalysisSummary,
    ParseFileDiagnostics,
    PipelineConfig,
    ProfileStageResult,
    RunResult,
)
from .output import (
    run_final_output_generation,
    run_artifact_generation,
    run_write_events_csv,
)
from .parsing import run_parsing
from .profiles import run_profile_computation
from .storage import (
    run_fail_run,
    run_finalize_run,
    run_start_run,
    run_store_aggregates,
    run_store_events,
)
from .text import NormalizationStats

logger = logging.getLogger(__name__)


def _build_trace_summary(
    input_path: Path,
    output_path: Path,
    source_file_count: int,
    event_count: int,
    multiline_merges: int,
    timings: Dict[str, float],
    normalization_stats: NormalizationStats,
) -> dict:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: сводки.
    
    Args:
        input_path (Path): Путь к входному файлу или директории с логами.
        output_path (Path): Путь к директории или файлу для записи результата.
        source_file_count (int): Значение `source_file_count`, используемое функцией при выполнении операции.
        event_count (int): Значение `event_count`, используемое функцией при выполнении операции.
        multiline_merges (int): Значение `multiline_merges`, используемое функцией при выполнении операции.
        timings (Dict[str, float]): Значение `timings`, используемое функцией при выполнении операции.
        normalization_stats (NormalizationStats): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        dict: Сводка трассировки запуска: идентификатор, профиль, вход, выход, тайминги этапов и диагностические счетчики.
    """
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "source_file_count": source_file_count,
        "events_parsed": event_count,
        "multiline_merges": multiline_merges,
        "timings_seconds": {name: round(value, 3) for name, value in timings.items()},
        "normalization": normalization_stats.snapshot(top_n=15),
    }


def _build_parser_diagnostics(
    file_results: list[ParseFileDiagnostics],
    events: List,
    analysis_summary,
) -> dict:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: парсера.
    
    Args:
        file_results (list[ParseFileDiagnostics]): Значение `file_results`, используемое функцией при выполнении операции.
        events (List): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        analysis_summary (Any): Сводная структура с метриками, статусами и диагностикой выполнения.
    
    Returns:
        dict: Агрегированная диагностика парсеров по файлам, включая качество, предупреждения и статистику fallback-разбора.
    """
    parser_counts = Counter(event.parser_profile for event in events)
    total_lines = sum(int(item.stats.get("total_lines", 0)) for item in file_results)
    total_events = sum(int(item.stats.get("total_events", 0)) for item in file_results)
    fallback_ratio = (
        sum(
            float(item.stats.get("fallback_ratio", 0.0))
            * max(int(item.stats.get("total_events", 0)), 1)
            for item in file_results
        )
        / max(total_events, 1)
    )
    warnings = []
    for item in file_results:
        for warning in item.warnings:
            warnings.append(f"{item.source_file}: {warning}")
            if len(warnings) >= 8:
                break
        if len(warnings) >= 8:
            break
    return {
        "selected_parsers": dict(parser_counts),
        "dominant_parser": parser_counts.most_common(1)[0][0] if parser_counts else "unknown",
        "mean_parser_confidence": round(getattr(analysis_summary, "mean_parser_confidence", 0.0), 3),
        "total_lines": total_lines,
        "total_events": total_events,
        "fallback_ratio": round(fallback_ratio, 3),
        "parse_quality": {
            "score": round(getattr(analysis_summary, "parse_quality_score", 0.0), 3),
            "label": getattr(analysis_summary, "parse_quality_label", "low"),
        },
        "incident_signal_quality": {
            "score": round(getattr(analysis_summary, "incident_signal_score", 0.0), 3),
            "label": getattr(analysis_summary, "incident_signal_label", "low"),
        },
        "warning_count": sum(len(item.warnings) for item in file_results),
        "warnings_sample": warnings,
        "files": [
            {
                "source_file": item.source_file,
                "parser_name": item.parser_name,
                "confidence": round(item.confidence, 3),
                "stats": item.stats,
            }
            for item in file_results[:10]
        ],
    }


def _build_analysis_summary(events: List, source_name: str, summary: dict) -> AnalysisSummary:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: сводки.
    
    Args:
        events (List): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        source_name (str): Человекочитаемое имя источника, используемое в сводках качества.
        summary (dict): Сводная структура с метриками, статусами и диагностикой выполнения.
    
    Returns:
        AnalysisSummary: Сводка качества анализа, построенная по событиям и количеству кластеров или профильных агрегатов.
    """
    quality = AnalysisQualityAccumulator(source_name=source_name)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        quality.add(event)
    cluster_like_count = (
        summary.get("cluster_count")
        or summary.get("bucket_count")
        or summary.get("traffic_row_count")
        or 0
    )
    return quality.build_summary(cluster_count=int(cluster_like_count))


def _ensure_profile_analysis_summary(
    events: List,
    source_name: str,
    profile_result: ProfileStageResult,
) -> AnalysisSummary:
    """Проверяет или подготавливает внутренний ресурс, необходимый для выполнения этапа. Область применения: профиля, сводки.
    
    Args:
        events (List): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        source_name (str): Человекочитаемое имя источника, используемое в сводках качества.
        profile_result (ProfileStageResult): Результат выполнения конвейера или промежуточного этапа, из которого берутся данные.
    
    Returns:
        AnalysisSummary: Сводка качества из результата профиля или заново рассчитанная fallback-сводка, если профиль ее не вернул.
    """
    analysis_summary_payload = profile_result.summary.get("analysis_summary")
    if analysis_summary_payload is None:
        analysis_summary = _build_analysis_summary(
            events,
            source_name=source_name,
            summary=profile_result.summary,
        )
        profile_result.summary["analysis_summary"] = asdict(analysis_summary)
        return analysis_summary
    return AnalysisSummary(**analysis_summary_payload)


def _build_artifact_paths(
    run_dir: Path,
    profile_result: ProfileStageResult,
    parquet_written: bool,
) -> Dict[str, str]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: артефакта.
    
    Args:
        run_dir (Path): Значение `run_dir`, используемое функцией при выполнении операции.
        profile_result (ProfileStageResult): Результат выполнения конвейера или промежуточного этапа, из которого берутся данные.
        parquet_written (bool): Значение `parquet_written`, используемое функцией при выполнении операции.
    
    Returns:
        Dict[str, str]: Пути к финальным продуктовыми артефактам запуска, доступным пользователю.
    """
    artifact_paths = {
        "run_summary_json": str(run_dir / "run_summary.json"),
        **profile_result.artifact_paths,
    }
    if parquet_written:
        artifact_paths["events_parquet"] = str(run_dir / "events.parquet")
    return artifact_paths


def _build_run_summary_payload(
    run_id: str,
    profile: str,
    input_path_obj: Path,
    run_dir: Path,
    event_count: int,
    trace_summary: dict,
    parser_diagnostics: dict,
    profile_fit: dict,
    profile_result: ProfileStageResult,
) -> dict:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: сводки, полезной нагрузки.
    
    Args:
        run_id (str): Идентификатор запуска, связывающий записи, артефакты и сводки.
        profile (str): Профиль анализа логов, определяющий набор вычислений и формат результата.
        input_path_obj (Path): Значение `input_path_obj`, используемое функцией при выполнении операции.
        run_dir (Path): Значение `run_dir`, используемое функцией при выполнении операции.
        event_count (int): Значение `event_count`, используемое функцией при выполнении операции.
        trace_summary (dict): Сводная структура с метриками, статусами и диагностикой выполнения.
        parser_diagnostics (dict): Значение `parser_diagnostics`, используемое функцией при выполнении операции.
        profile_fit (dict): Значение `profile_fit`, используемое функцией при выполнении операции.
        profile_result (ProfileStageResult): Результат выполнения конвейера или промежуточного этапа, из которого берутся данные.
    
    Returns:
        dict: JSON-совместимая сводка запуска со статусом, метриками, качеством, артефактами и диагностикой.
    """
    return {
        "run_id": run_id,
        "profile": profile,
        "status": "completed",
        "input_path": str(input_path_obj),
        "output_dir": str(run_dir),
        "event_count": event_count,
        "trace_summary": trace_summary,
        "parser_diagnostics": parser_diagnostics,
        "profile_fit": profile_fit,
        "profile_summary": profile_result.summary,
    }


def run_pipeline(
    input_path: str,
    profile: str = "incidents",
    out_dir: Optional[str] = None,
    clean_out: bool = False,
    sample_events: int = 0,
    semantic: str = "on",
    semantic_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    semantic_min_cluster_size: int = 3,
    semantic_min_samples: int | None = None,
    agent: str = "off",
    agent_question: str | None = None,
    agent_provider: str = "none",
) -> RunResult:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы.
    
    Args:
        input_path (str): Путь к входному файлу или директории с логами.
        profile (str, optional): Профиль анализа логов, определяющий набор вычислений и формат результата.
        out_dir (Optional[str], optional): Базовая директория, куда записываются результаты выполнения.
        clean_out (bool, optional): Значение `clean_out`, используемое функцией при выполнении операции.
        sample_events (int, optional): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        semantic (str, optional): Значение `semantic`, используемое функцией при выполнении операции.
        semantic_model (str, optional): Значение `semantic_model`, используемое функцией при выполнении операции.
        semantic_min_cluster_size (int, optional): Значение `semantic_min_cluster_size`, используемое функцией при выполнении операции.
        semantic_min_samples (int | None, optional): Значение `semantic_min_samples`, используемое функцией при выполнении операции.
        agent (str, optional): Значение `agent`, используемое функцией при выполнении операции.
        agent_question (str | None, optional): Значение `agent_question`, используемое функцией при выполнении операции.
        agent_provider (str, optional): Имя провайдера внешней модели, для которого строится конфигурация.
    
    Returns:
        RunResult: Итог запуска конвейера: run_id, статус, профиль, счетчик событий, пути к БД, директории и артефактам.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    del sample_events
    config = PipelineConfig(
        input_path=Path(input_path),  # где лежит лог-файл или директория с логами
        profile=profile,  # профиль, по которому будет проходить обработка
        out_dir=out_dir,  # куда будут записаны обработанные логи и отчеты
        clean_out=clean_out,  # очищать ли директорию вывода перед запуском
        semantic=semantic,  # включать ли семантическую кластеризацию
        semantic_model=semantic_model,  # модель для семантического анализа сообщений
        semantic_min_cluster_size=semantic_min_cluster_size,  # минимальный размер кластера
        semantic_min_samples=semantic_min_samples,  # минимальное число соседей кластера
        agent=agent,  # запускать ли агентный анализ после пайплайна
        agent_question=agent_question,  # вопрос, который агент разберет по результатам
        agent_provider=agent_provider,  # провайдер агентного анализа
    )

    try:
        context = run_start_run(config)
        logger.info(
            "run_started: run_id=%s profile=%s input=%s output_dir=%s db_path=%s semantic=%s",
            context.run_id,
            context.config.profile,
            str(context.input_path),
            str(context.run_dir),
            str(context.repository.db_path),
            context.config.semantic,
        )

        context = run_parsing(context)
        context = run_event_building(context)
        context = run_write_events_csv(context)
        context = run_store_events(context)
        context = run_profile_computation(context)
        context = run_store_aggregates(context)
        context = run_artifact_generation(context)

        parse_result = context.parse_result
        event_build_result = context.event_build_result
        profile_result = context.profile_result
        if parse_result is None or event_build_result is None or profile_result is None:
            raise RuntimeError("Pipeline context was not populated by required stages.")

        trace_summary = _build_trace_summary(
            input_path=context.input_path,
            output_path=context.run_dir,
            source_file_count=len(parse_result.source_files),
            event_count=event_build_result.event_count,
            multiline_merges=event_build_result.multiline_merges,
            timings=context.timings,
            normalization_stats=context.normalization_stats,
        )
        analysis_summary = _ensure_profile_analysis_summary(
            events=context.events,
            source_name=context.input_path.name,
            profile_result=profile_result,
        )
        parser_diagnostics = _build_parser_diagnostics(parse_result.file_results, context.events, analysis_summary)
        profile_fit = assess_profile_fit(context.events, selected_profile=context.config.profile)

        context.artifact_paths = _build_artifact_paths(
            run_dir=context.run_dir,
            profile_result=profile_result,
            parquet_written=context.parquet_written,
        )

        run_summary = _build_run_summary_payload(
            run_id=context.run_id,
            profile=context.config.profile,
            input_path_obj=context.input_path,
            run_dir=context.run_dir,
            event_count=event_build_result.event_count,
            trace_summary=trace_summary,
            parser_diagnostics=parser_diagnostics,
            profile_fit=profile_fit,
            profile_result=profile_result,
        )
        context.run_summary = run_summary

        context = run_agent_pipeline(context)
        context = run_quality_validation(context)
        context = run_final_output_generation(context)

        context = run_finalize_run(context)
        logger.info(
            "run_completed: run_id=%s profile=%s events=%d artifacts=%d",
            context.run_id,
            context.config.profile,
            event_build_result.event_count,
            len(context.artifact_paths),
        )
        if context.final_summary is None or context.execution_quality is None:
            raise RuntimeError("Final product output was not built.")

        return RunResult(
            run_id=context.run_id,
            profile=context.config.profile,
            status="completed",
            output_dir=str(context.run_dir),
            db_path=str(context.repository.db_path),
            event_count=event_build_result.event_count,
            summary=context.final_summary,
            findings=context.findings,
            quality=context.execution_quality,
            artifact_paths=context.artifact_paths,
            run_summary=context.run_summary or run_summary,
            agent_result=context.agent_result.as_dict() if context.agent_result else None,
        )
    except Exception as error:
        if context is not None:
            try:
                run_fail_run(context, error)
            except Exception:
                logger.exception("run_fail_marking_error: run_id=%s", context.run_id)
        raise


def main() -> None:
    """Выполняет вспомогательную операцию для логики проекта.

    Args:
        Нет параметров.

    Returns:
        None: Функция выполняет команду и не возвращает значение вызывающему коду.
    """
    from .cli import main as cli_main

    cli_main()


def build_parser():
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: парсера.

    Args:
        Нет параметров.

    Returns:
        argparse.ArgumentParser: Настроенный парсер аргументов командной строки.
    """
    from .cli import build_parser as cli_build_parser

    return cli_build_parser()


__all__ = [
    "build_parser",
    "main",
    "run_pipeline",
]


if __name__ == "__main__":
    main()
