from __future__ import annotations

"""Точки входа этапов конвейера для записи общих артефактов."""

import csv
import json
import logging
import re
import time
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from ..domain import Event, PipelineContext
from .reporting import (
    event_to_row,
    open_events_csv_writer,
    write_analysis_summary_json,
    write_clusters_csv,
    write_events_parquet,
    write_llm_ready_clusters_json,
    write_semantic_clusters_csv,
    write_top_clusters_md,
)

logger = logging.getLogger(__name__)

_PATH_ID_RE = re.compile(r"/(?:(?:\d+)|(?:[0-9a-fA-F]{8,})|(?:[0-9a-fA-F-]{8,}))(?:/|$)")
_WHITESPACE_RE = re.compile(r"\s+")


def run_write_events_csv(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: событий, CSV.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_write_events_csv`.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if context.event_build_result is None:
        raise RuntimeError("Event building must run before events CSV writing.")
    context.timings["write_events_csv"] = 0.0
    logger.info("events_csv_skipped: run_id=%s mode=product_output_only", context.run_id)
    return context


def _write_markdown(path: Path, lines: List[str]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        lines (List[str]): Список строк лога, обрабатываемых функцией.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _normalize_heatmap_text(value: str | None) -> str:
    """Нормализует внутреннее значение к каноническому виду для дальнейших расчетов. Область применения: тепловой карты.
    
    Args:
        value (str | None): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        str: Очищенный текст для тепловой карты; `unknown`, если значение пустое.
    """
    if not value:
        return "unknown"
    normalized = _WHITESPACE_RE.sub(" ", value).strip()
    return normalized[:120] if normalized else "unknown"


def _normalize_heatmap_path(path: str | None) -> str | None:
    """Нормализует внутреннее значение к каноническому виду для дальнейших расчетов. Область применения: тепловой карты, пути.
    
    Args:
        path (str | None): Путь к файлу или артефакту, с которым работает функция.
    
    Returns:
        str | None: Нормализованный HTTP-путь без query-string и завершающего слеша; None для пустого пути.
    """
    if not path:
        return None
    raw_path = urlsplit(path).path or path
    raw_path = raw_path.strip()
    if not raw_path:
        return None
    normalized = _PATH_ID_RE.sub("/{id}/", raw_path)
    normalized = re.sub(r"/+", "/", normalized)
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized or "/"


def _derive_heatmap_operation(event: Event) -> str:
    """Выполняет вспомогательную операцию для тепловой карты.
    
    Args:
        event (Event): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
    
    Returns:
        str: Название операции для тепловой карты: компонент, HTTP-метод с путем или запасной источник события.
    """
    normalized_path = _normalize_heatmap_path(event.path)
    if normalized_path:
        method = _normalize_heatmap_text(event.method).upper() if getattr(event, "method", None) else None
        return f"{method} {normalized_path}" if method else normalized_path
    if event.message:
        message_head = event.message.split(" - ", 1)[0]
        return _normalize_heatmap_text(message_head)
    if event.component:
        return _normalize_heatmap_text(event.component)
    return "unknown"


def _write_heatmap_timeseries_csv(path: Path, rows: List[dict]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: тепловой карты, CSV.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    fieldnames = ["bucket_start", "component", "operation", "hits", "qps", "p95_latency_ms"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_heatmap_findings_json(path: Path, findings: dict) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: тепловой карты, JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        findings (dict): Значение `findings`, используемое функцией при выполнении операции.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    path.write_text(json.dumps(findings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_top_hotspots_md(path: Path, rows: List[dict], events: List[Event], findings: dict) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: Markdown.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        findings (dict): Значение `findings`, используемое функцией при выполнении операции.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    component_count = len({_normalize_heatmap_text(event.component) for event in events})
    operation_count = len({_derive_heatmap_operation(event) for event in events})
    top_components = findings.get("top_components", [])
    top_operations = findings.get("top_operations", [])
    lines = [
        "# Heatmap Hotspots",
        "",
        f"- Events: {len(events)}",
        f"- Components seen: {component_count}",
        f"- Operations seen: {operation_count}",
        "",
        "## Hottest buckets",
        "",
    ]
    if not rows:
        lines.append("No buckets were produced.")
    else:
        for index, row in enumerate(rows[:10], start=1):
            latency = "n/a" if row["p95_latency_ms"] is None else f"{row['p95_latency_ms']:.3f} ms"
            lines.extend(
                [
                    f"### {index}. {row['bucket_start']}",
                    f"- component: {row['component']}",
                    f"- operation: {row['operation']}",
                    f"- hits: {row['hits']}",
                    f"- qps: {row['qps']}",
                    f"- p95 latency: {latency}",
                    "",
                ]
            )
    lines.extend(["## Top components", ""])
    for item in top_components:
        lines.append(f"- {item['value']}: {item['hits']}")
    lines.extend(["", "## Top operations", ""])
    for item in top_operations:
        lines.append(f"- {item['value']}: {item['hits']}")
    _write_markdown(path, lines)


def _write_traffic_summary_csv(path: Path, rows: List[dict]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: трафика, сводки, CSV.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    fieldnames = [
        "method",
        "path",
        "http_status",
        "hits",
        "unique_ips",
        "p95_latency_ms",
        "p99_latency_ms",
        "avg_response_size",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_latency_report_md(path: Path, rows: List[dict]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: задержки, Markdown.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    lines = ["# Traffic Latency Report", "", "## Top endpoints by latency", ""]
    if not rows:
        lines.append("No traffic rows were produced.")
    else:
        sorted_rows = sorted(rows, key=lambda item: item["p95_latency_ms"] or 0, reverse=True)
        for index, row in enumerate(sorted_rows[:10], start=1):
            lines.extend(
                [
                    f"### {index}. {row['method']} {row['path']}",
                    f"- hits: {row['hits']}",
                    f"- status: {row['http_status'] if row['http_status'] is not None else 'n/a'}",
                    f"- p95 latency: {row['p95_latency_ms'] if row['p95_latency_ms'] is not None else 'n/a'}",
                    f"- p99 latency: {row['p99_latency_ms'] if row['p99_latency_ms'] is not None else 'n/a'}",
                    "",
                ]
            )
    _write_markdown(path, lines)


def _write_suspicious_traffic_md(path: Path, anomalies: List[dict]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: трафика, Markdown.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        anomalies (List[dict]): Значение `anomalies`, используемое функцией при выполнении операции.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    lines = ["# Suspicious Traffic", ""]
    if not anomalies:
        lines.append("No suspicious patterns were detected.")
    else:
        for index, anomaly in enumerate(anomalies, start=1):
            lines.extend(
                [
                    f"## {index}. {anomaly['title']}",
                    f"- type: {anomaly['anomaly_type']}",
                    f"- severity: {anomaly['severity']}",
                    f"- details: {anomaly['details']}",
                    "",
                ]
            )
    _write_markdown(path, lines)


def _write_incidents_artifacts(context: PipelineContext, payload: dict) -> dict[str, str]:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: инцидентов, артефактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
        payload (dict): Словарь с исходными или уже подготовленными данными для преобразования.
    
    Returns:
        dict[str, str]: Пути к артефактам профиля инцидентов, записанным в директорию запуска.
    """
    clusters_path = context.run_dir / "clusters.csv"
    semantic_path = context.run_dir / "semantic_clusters.csv"
    top_incidents_path = context.run_dir / "top_incidents.md"
    llm_path = context.run_dir / "llm_ready_clusters.json"
    analysis_path = context.run_dir / "analysis_summary.json"

    write_clusters_csv(clusters_path, payload["clusters"])
    write_semantic_clusters_csv(semantic_path, payload["semantic_clusters"])
    write_llm_ready_clusters_json(llm_path, payload["top_clusters"])
    write_top_clusters_md(
        top_incidents_path,
        payload["top_clusters"],
        event_count=len(context.events),
        cluster_count=len(payload["clusters"]),
        analysis_summary=payload["analysis_summary"],
        semantic_note=payload["semantic_note"],
    )
    write_analysis_summary_json(analysis_path, payload["analysis_summary"])
    return {
        "clusters_csv": str(clusters_path),
        "semantic_clusters_csv": str(semantic_path),
        "top_incidents_md": str(top_incidents_path),
        "llm_ready_clusters_json": str(llm_path),
        "analysis_summary_json": str(analysis_path),
    }


def _write_heatmap_artifacts(context: PipelineContext, payload: dict) -> dict[str, str]:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: тепловой карты, артефактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
        payload (dict): Словарь с исходными или уже подготовленными данными для преобразования.
    
    Returns:
        dict[str, str]: Пути к CSV, JSON и Markdown-артефактам тепловой карты.
    """
    timeseries_path = context.run_dir / "heatmap_timeseries.csv"
    hotspots_path = context.run_dir / "top_hotspots.md"
    findings_path = context.run_dir / "heatmap_findings.json"

    _write_heatmap_timeseries_csv(timeseries_path, payload["rows"])
    _write_top_hotspots_md(hotspots_path, payload["rows"], context.events, payload["findings"])
    _write_heatmap_findings_json(findings_path, payload["findings"])
    return {
        "heatmap_timeseries_csv": str(timeseries_path),
        "top_hotspots_md": str(hotspots_path),
        "heatmap_findings_json": str(findings_path),
    }


def _write_traffic_artifacts(context: PipelineContext, payload: dict) -> dict[str, str]:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: трафика, артефактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
        payload (dict): Словарь с исходными или уже подготовленными данными для преобразования.
    
    Returns:
        dict[str, str]: Пути к CSV и Markdown-артефактам профиля трафика.
    """
    summary_path = context.run_dir / "traffic_summary.csv"
    latency_path = context.run_dir / "latency_report.md"
    suspicious_path = context.run_dir / "suspicious_traffic.md"

    _write_traffic_summary_csv(summary_path, payload["rows"])
    _write_latency_report_md(latency_path, payload["rows"])
    _write_suspicious_traffic_md(suspicious_path, payload["anomalies"])
    return {
        "traffic_summary_csv": str(summary_path),
        "latency_report_md": str(latency_path),
        "suspicious_traffic_md": str(suspicious_path),
    }


def run_artifact_generation(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: артефакта.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_artifact_generation`.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    profile_result = context.profile_result
    if profile_result is None:
        raise RuntimeError("Profile computation must run before artifact generation.")

    profile_result.payload["artifact_paths"] = {}
    context.timings["write_profile_artifacts"] = 0.0
    context.parquet_written = False
    context.timings["write_parquet"] = 0.0
    logger.info(
        "profile_artifacts_skipped: run_id=%s profile=%s mode=product_output_only",
        context.run_id,
        profile_result.profile,
    )
    return context
