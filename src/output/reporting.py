from __future__ import annotations

"""Писатели выходных артефактов CSV, JSON, Markdown и опционального Parquet."""

import csv
from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional

from ..domain import AnalysisSummary, ClusterSummary, Event, SemanticClusterSummary

_EVENT_FIELDNAMES = [
    "event_id",
    "run_id",
    "source_file",
    "parser_profile",
    "parser_confidence",
    "timestamp",
    "level",
    "component",
    "message",
    "stacktrace",
    "raw_text",
    "line_count",
    "normalized_message",
    "signature_hash",
    "embedding_text",
    "request_id",
    "trace_id",
    "exception_type",
    "stack_frames",
    "http_status",
    "method",
    "path",
    "latency_ms",
    "response_size",
    "client_ip",
    "user_agent",
    "attributes_json",
    "is_incident",
]


def _write_csv_rows(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: CSV, строк.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        fieldnames (list[str]): Порядок и имена колонок, используемые при записи CSV-файла.
        rows (Iterable[dict[str, Any]]): Строки табличных данных, которые нужно записать, агрегировать или проверить.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_json(path: Path, payload: Any) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        payload (Any): Словарь с исходными или уже подготовленными данными для преобразования.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def format_timestamp(value: Any) -> str:
    """Преобразует значение в строковое представление для отчетов или вывода. Область применения: временной метки.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        str: ISO-строка временной метки; пустая строка, если значение отсутствует.
    """
    return value.isoformat(sep=" ") if value else ""


def event_to_row(event: Event) -> dict:
    """Выполняет вспомогательную операцию для события, строки.
    
    Args:
        event (Event): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
    
    Returns:
        dict: CSV-строка события с основными полями, HTTP-атрибутами и сериализованными дополнительными данными.
    """
    return {
        "event_id": event.event_id,
        "run_id": event.run_id,
        "source_file": event.source_file,
        "parser_profile": event.parser_profile,
        "parser_confidence": event.parser_confidence,
        "timestamp": format_timestamp(event.timestamp),
        "level": event.level or "",
        "component": event.component or "",
        "message": event.message,
        "stacktrace": event.stacktrace,
        "raw_text": event.raw_text,
        "line_count": event.line_count,
        "normalized_message": event.normalized_message,
        "signature_hash": event.signature_hash,
        "embedding_text": event.embedding_text,
        "request_id": event.request_id or "",
        "trace_id": event.trace_id or "",
        "exception_type": event.exception_type or "",
        "stack_frames": " | ".join(event.stack_frames),
        "http_status": event.http_status or "",
        "method": event.method or "",
        "path": event.path or "",
        "latency_ms": "" if event.latency_ms is None else event.latency_ms,
        "response_size": "" if event.response_size is None else event.response_size,
        "client_ip": event.client_ip or "",
        "user_agent": event.user_agent or "",
        "attributes_json": json.dumps(event.attributes, ensure_ascii=False, sort_keys=True),
        "is_incident": str(event.is_incident).lower(),
    }


def write_events_csv(path: Path, events: Iterable[Event]) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: событий, CSV.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        events (Iterable[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    _write_csv_rows(path, _EVENT_FIELDNAMES, (event_to_row(event) for event in events))


@contextmanager
def open_events_csv_writer(path: Path) -> Iterator[csv.DictWriter]:
    """Открывает ресурс и возвращает объект для последующей записи или чтения. Область применения: событий, CSV.
    
    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
    
    Returns:
        Iterator[csv.DictWriter]: Контекстный менеджер с CSV-writer для потоковой записи строк событий.
    """
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_EVENT_FIELDNAMES)
        writer.writeheader()
        yield writer


def write_clusters_csv(path: Path, clusters: Iterable[ClusterSummary]) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: кластеров, CSV.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        clusters (Iterable[ClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    fieldnames = [
        "cluster_id",
        "hits",
        "first_seen",
        "last_seen",
        "parser_profiles",
        "source_files",
        "sample_messages",
        "example_exception",
        "exception_type",
        "top_stack_frames",
        "representative_raw",
        "representative_normalized",
        "representative_signature_text",
        "levels",
        "incident_hits",
        "confidence_score",
        "confidence_label",
        "clustering_method",
    ]
    _write_csv_rows(
        path,
        fieldnames,
        (
            {
                "cluster_id": cluster.cluster_id,
                "hits": cluster.hits,
                "first_seen": format_timestamp(cluster.first_seen),
                "last_seen": format_timestamp(cluster.last_seen),
                "parser_profiles": cluster.parser_profiles,
                "source_files": cluster.source_files,
                "sample_messages": cluster.sample_messages,
                "example_exception": cluster.example_exception or "",
                "exception_type": cluster.example_exception or "",
                "top_stack_frames": cluster.top_stack_frames,
                "representative_raw": cluster.representative_raw,
                "representative_normalized": cluster.representative_normalized,
                "representative_signature_text": cluster.representative_signature_text,
                "levels": cluster.levels,
                "incident_hits": cluster.incident_hits,
                "confidence_score": cluster.confidence_score,
                "confidence_label": cluster.confidence_label,
                "clustering_method": cluster.clustering_method,
            }
            for cluster in clusters
        ),
    )


def write_top_clusters_md(
    path: Path,
    clusters: List[ClusterSummary],
    event_count: int,
    cluster_count: int,
    analysis_summary: Optional[AnalysisSummary] = None,
    semantic_note: Optional[str] = None,
) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: кластеров, Markdown.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        clusters (List[ClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.
        event_count (int): Значение `event_count`, используемое функцией при выполнении операции.
        cluster_count (int): Количество найденных кластеров, учитываемое в итоговой сводке.
        analysis_summary (Optional[AnalysisSummary], optional): Сводная структура с метриками, статусами и диагностикой выполнения.
        semantic_note (Optional[str], optional): Значение `semantic_note`, используемое функцией при выполнении операции.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    lines = [
        "# LogCopilot Top Clusters",
        "",
        f"- Events: {event_count}",
        f"- Signature clusters: {cluster_count}",
    ]
    if analysis_summary:
        lines.extend(
            [
                f"- Parse quality: {analysis_summary.parse_quality_label} ({analysis_summary.parse_quality_score:.2f})",
                f"- Incident signal quality: {analysis_summary.incident_signal_label} ({analysis_summary.incident_signal_score:.2f})",
                f"- Timestamp coverage: {analysis_summary.timestamp_coverage:.1%}",
                f"- Level coverage: {analysis_summary.level_coverage:.1%}",
                f"- Exception coverage: {analysis_summary.exception_coverage:.1%}",
                f"- Stacktrace coverage: {analysis_summary.stacktrace_coverage:.1%}",
                f"- Fallback parser rate: {analysis_summary.fallback_profile_rate:.1%}",
                f"- Mean parser confidence: {analysis_summary.mean_parser_confidence:.2f}",
            ]
        )
    if semantic_note:
        lines.append(f"- Semantic clustering: {semantic_note}")
    lines.extend(["", "## Top-10 incidents", ""])

    if not clusters:
        lines.append("No incident-like clusters were found.")
    else:
        for index, cluster in enumerate(clusters[:10], start=1):
            lines.append(f"### {index}. {cluster.cluster_id}")
            lines.append(f"- Hits: {cluster.hits}")
            lines.append(f"- Incident hits: {cluster.incident_hits}")
            lines.append(f"- First seen: {format_timestamp(cluster.first_seen) or 'n/a'}")
            lines.append(f"- Last seen: {format_timestamp(cluster.last_seen) or 'n/a'}")
            lines.append(f"- Confidence: {cluster.confidence_label} ({cluster.confidence_score:.2f})")
            lines.append(f"- Parser profiles: {cluster.parser_profiles or 'n/a'}")
            lines.append(f"- Levels: {cluster.levels or 'n/a'}")
            lines.append(f"- Exception: {cluster.example_exception or 'n/a'}")
            lines.append(f"- Source files: {cluster.source_files or 'n/a'}")
            lines.append("- Sample messages:")
            for sample in cluster.sample_messages.split(" || "):
                lines.append(f"  - {sample}")
            lines.append("")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_semantic_clusters_csv(
    path: Path, clusters: Iterable[SemanticClusterSummary]
) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: семантического анализа, кластеров, CSV.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        clusters (Iterable[SemanticClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    fieldnames = [
        "semantic_cluster_id",
        "signature_hash",
        "hits",
        "representative_text",
        "member_signature_hashes",
        "avg_cosine_similarity",
    ]
    _write_csv_rows(
        path,
        fieldnames,
        (
            {
                "semantic_cluster_id": cluster.semantic_cluster_id,
                "signature_hash": cluster.signature_hash,
                "hits": cluster.hits,
                "representative_text": cluster.representative_text,
                "member_signature_hashes": cluster.member_signature_hashes,
                "avg_cosine_similarity": cluster.avg_cosine_similarity,
            }
            for cluster in clusters
        ),
    )


def write_events_parquet(path: Path, events: List[Event]) -> bool:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: событий.
    
    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        bool: True, если Parquet-файл успешно записан; False, если зависимость pyarrow недоступна.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        return False

    rows = [
        {
            "event_id": event.event_id,
            "source_file": event.source_file,
            "parser_profile": event.parser_profile,
            "parser_confidence": event.parser_confidence,
            "timestamp": format_timestamp(event.timestamp),
            "level": event.level or "",
            "component": event.component or "",
            "message": event.message,
            "stacktrace": event.stacktrace,
            "raw_text": event.raw_text,
            "line_count": event.line_count,
            "normalized_message": event.normalized_message,
            "signature_hash": event.signature_hash,
            "embedding_text": event.embedding_text,
            "request_id": event.request_id or "",
            "trace_id": event.trace_id or "",
            "exception_type": event.exception_type or "",
            "stack_frames": event.stack_frames,
            "http_status": event.http_status,
            "method": event.method or "",
            "path": event.path or "",
            "latency_ms": event.latency_ms,
            "response_size": event.response_size,
            "client_ip": event.client_ip or "",
            "user_agent": event.user_agent or "",
            "attributes_json": json.dumps(event.attributes, ensure_ascii=False, sort_keys=True),
            "is_incident": event.is_incident,
        }
        for event in events
    ]
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path)
    return True


def write_analysis_summary_json(path: Path, summary: AnalysisSummary) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: сводки, JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        summary (AnalysisSummary): Сводная структура с метриками, статусами и диагностикой выполнения.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    _write_json(path, asdict(summary))


def write_llm_ready_clusters_json(path: Path, clusters: List[ClusterSummary]) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: кластеров, JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        clusters (List[ClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    payload = [
        {
            "cluster_id": cluster.cluster_id,
            "hits": cluster.hits,
            "incident_hits": cluster.incident_hits,
            "first_seen": format_timestamp(cluster.first_seen),
            "last_seen": format_timestamp(cluster.last_seen),
            "confidence_score": cluster.confidence_score,
            "confidence_label": cluster.confidence_label,
            "parser_profiles": cluster.parser_profiles,
            "levels": cluster.levels,
            "exception_type": cluster.example_exception,
            "top_stack_frames": cluster.top_stack_frames,
            "representative_raw": cluster.representative_raw,
            "representative_normalized": cluster.representative_normalized,
            "representative_signature_text": cluster.representative_signature_text,
            "source_files": cluster.source_files,
            "sample_messages": [sample for sample in cluster.sample_messages.split(" || ") if sample],
        }
        for cluster in clusters
    ]
    _write_json(path, payload)


def write_debug_samples_md(path: Path, events: List[Event]) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: Markdown.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    lines = ["# Debug Samples", ""]
    if not events:
        lines.append("No debug samples were captured.")
    for index, event in enumerate(events, start=1):
        lines.extend(
            [
                f"## Sample {index}",
                "",
                f"- source_file: {event.source_file}",
                f"- parser_profile: {event.parser_profile}",
                f"- cluster_id: {event.signature_hash}",
                f"- level: {event.level or 'n/a'}",
                f"- component: {event.component or 'n/a'}",
                "",
                "### Raw",
                "",
                "```text",
                event.raw_text[:3000],
                "```",
                "",
                "### Normalized",
                "",
                "```text",
                event.normalized_message,
                "```",
                "",
                "### Signature / Embedding Text",
                "",
                "```text",
                event.embedding_text,
                "```",
                "",
            ]
        )
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_trace_summary_json(path: Path, trace_summary: dict) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: сводки, JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        trace_summary (dict): Сводная структура с метриками, статусами и диагностикой выполнения.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    _write_json(path, trace_summary)


def write_manifest_json(path: Path, payload: dict) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        payload (dict): Словарь с исходными или уже подготовленными данными для преобразования.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    _write_json(path, payload)


def write_run_summary_json(path: Path, payload: dict) -> None:
    """Записывает данные в файл или артефакт в формате, ожидаемом остальными этапами. Область применения: сводки, JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        payload (dict): Словарь с исходными или уже подготовленными данными для преобразования.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    _write_json(path, payload)
