from __future__ import annotations

"""Компактные детерминированные факты для агентского этапа с учетом профиля."""

from dataclasses import asdict, is_dataclass
import json
import logging
import time
from typing import Any, Dict, Iterable, List

from ..domain import AgentInputContext, PipelineContext
from .config import (
    AGENT_CONTEXT_LIMITS,
    MAX_AGENT_LIST_ITEMS,
    MAX_AGENT_TEXT_CHARS,
    MAX_HEATMAP_CARDS,
    MAX_INCIDENT_CARDS,
    MAX_SAMPLE_MESSAGES,
    MAX_TRAFFIC_CARDS,
)

logger = logging.getLogger(__name__)


def _clip(value: Any, limit: int = MAX_AGENT_TEXT_CHARS) -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        str: Однострочный текст без переводов строк, обрезанный до `limit` символов с многоточием при переполнении.
    """
    if value is None:
        return ""
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)].rstrip() + "..."


def _dict(value: Any) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Dict[str, Any]: Копия входного словаря или пустой словарь, если значение не является mapping.
    """
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    return dict(value) if isinstance(value, dict) else {}


def _field(value: Any, name: str, default: Any = None) -> Any:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
        name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
        default (Any, optional): Значение по умолчанию, возвращаемое при невозможности корректного преобразования.
    
    Returns:
        Any: Значение поля из словаря или атрибута объекта; default, если поле отсутствует.
    """
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _take(items: Iterable[Any] | None, limit: int) -> List[Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        items (Iterable[Any] | None): Коллекция элементов, которую нужно ограничить, преобразовать или агрегировать.
        limit (int): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[Any]: Первые `limit` элементов входной коллекции; пустой список, если коллекция отсутствует.
    """
    result = []
    for item in items or []:
        result.append(item)
        if len(result) >= limit:
            break
    return result


def _scalars(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        payload (Dict[str, Any]): Словарь с исходными или уже подготовленными данными для преобразования.
    
    Returns:
        Dict[str, Any]: Подмножество payload только со скалярными JSON-совместимыми значениями.
    """
    return {
        key: value
        for key, value in payload.items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }


def _run_summary(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет внутренний этап обработки и возвращает подготовленный результат. Область применения: сводки.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: JSON-совместимая сводка с ключевыми метриками и диагностикой.
    """
    summary = context.run_summary or {}
    return {
        "run_id": context.run_id,
        "profile": context.config.profile,
        "status": summary.get("status", "completed"),
        "event_count": summary.get("event_count", len(context.events)),
        "input_name": context.input_path.name,
        "profile_summary": _scalars(_dict(summary.get("profile_summary"))),
    }


def _parser_diagnostics(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для парсера.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Диагностика парсинга для агента: основной парсер, качество разбора, качество incident-сигнала и предупреждения.
    """
    diagnostics = _dict((context.run_summary or {}).get("parser_diagnostics"))
    return {
        "dominant_parser": diagnostics.get("dominant_parser", "unknown"),
        "selected_parsers": diagnostics.get("selected_parsers", {}),
        "mean_parser_confidence": diagnostics.get("mean_parser_confidence"),
        "total_lines": diagnostics.get("total_lines"),
        "total_events": diagnostics.get("total_events"),
        "fallback_ratio": diagnostics.get("fallback_ratio"),
        "parse_quality": _dict(diagnostics.get("parse_quality")),
        "incident_signal_quality": _dict(diagnostics.get("incident_signal_quality")),
        "warning_count": diagnostics.get("warning_count", 0),
        "warnings_sample": [_clip(item, 240) for item in _take(diagnostics.get("warnings_sample"), 3)],
    }


def _profile_fit(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для профиля.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Оценка пригодности выбранного профиля для агента: метка, рекомендуемый профиль и объясняющие метрики.
    """
    profile_fit = _dict((context.run_summary or {}).get("profile_fit"))
    compact = _scalars(profile_fit)
    for key in ("reasons", "signals", "recommendations"):
        if isinstance(profile_fit.get(key), list):
            compact[key] = [_clip(item, 240) for item in _take(profile_fit[key], 5)]
    return compact


def _sample_messages(value: Any) -> List[str]:
    """Выполняет вспомогательную операцию для сообщений.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        List[str]: Список текстовых сообщений, очищенных и ограниченных заданным лимитом.
    """
    if isinstance(value, str):
        samples = [item.strip() for item in value.split(" || ") if item.strip()]
    elif isinstance(value, list):
        samples = [str(item).strip() for item in value if str(item).strip()]
    elif value:
        samples = [str(value).strip()]
    else:
        samples = []
    return [_clip(item, 260) for item in samples[:MAX_SAMPLE_MESSAGES]]


def _incident_cluster(cluster: Any) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для инцидента, кластера.
    
    Args:
        cluster (Any): Один кластер событий, который нужно преобразовать или описать.
    
    Returns:
        Dict[str, Any]: Компактное описание incident-кластера с id, hit-счетчиками, временем, уверенностью и примерами сообщений.
    """
    representative = (
        _field(cluster, "representative_signature_text")
        or _field(cluster, "representative_normalized")
        or _field(cluster, "representative_text")
        or _field(cluster, "representative_raw")
        or ""
    )
    return {
        "cluster_id": _clip(_field(cluster, "cluster_id", ""), 120),
        "hits": int(_field(cluster, "hits", 0) or 0),
        "incident_hits": int(_field(cluster, "incident_hits", 0) or 0),
        "confidence_score": float(_field(cluster, "confidence_score", 0.0) or 0.0),
        "confidence_label": _field(cluster, "confidence_label", "low"),
        "first_seen": _clip(_field(cluster, "first_seen", ""), 80),
        "last_seen": _clip(_field(cluster, "last_seen", ""), 80),
        "levels": _clip(_field(cluster, "levels", ""), 220),
        "exception_type": _field(cluster, "example_exception") or _field(cluster, "exception_type"),
        "top_stack_frames": _clip(_field(cluster, "top_stack_frames", ""), 420),
        "source_files": _clip(_field(cluster, "source_files", ""), 260),
        "representative_text": _clip(representative, 420),
        "sample_messages": _sample_messages(_field(cluster, "sample_messages", [])),
    }


def _incidents_facts(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для инцидентов, фактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Компактный словарь фактов для выбранного профиля агентского этапа.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    profile_result = context.profile_result
    if profile_result is None:
        raise RuntimeError("Profile computation must run before agent facts.")
    payload = profile_result.payload
    summary = _dict(profile_result.summary)
    analysis_summary = _scalars(_dict(summary.get("analysis_summary")))
    clusters = payload.get("top_clusters") or payload.get("clusters") or []
    cluster_facts = [_incident_cluster(cluster) for cluster in _take(clusters, MAX_INCIDENT_CARDS)]
    return {
        "profile": "incidents",
        "summary": _scalars(summary),
        "analysis_summary": analysis_summary,
        "semantic_note": payload.get("semantic_note", ""),
        "top_cluster_candidates": [
            {
                "cluster_id": item["cluster_id"],
                "hits": item["hits"],
                "incident_hits": item["incident_hits"],
                "confidence_label": item["confidence_label"],
                "exception_type": item["exception_type"],
            }
            for item in cluster_facts
        ],
        "compact_llm_ready_cluster_facts": cluster_facts,
    }


def _counter_items(items: Any, limit: int = MAX_AGENT_LIST_ITEMS) -> List[Dict[str, Any]]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        items (Any): Коллекция элементов, которую нужно ограничить, преобразовать или агрегировать.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[Dict[str, Any]]: Список словарей с нормализованными фактами или строками отчета.
    """
    return [
        {"value": _clip(_dict(item).get("value", "unknown"), 220), "hits": _dict(item).get("hits", 0)}
        for item in _take(items, limit)
    ]


def _hotspot(row: Dict[str, Any]) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        row (Dict[str, Any]): Одна строка табличных данных, из которой строится объект результата.
    
    Returns:
        Dict[str, Any]: Компактное описание горячего бакета тепловой карты с временем, компонентом, операцией, ошибками и задержкой.
    """
    return {
        "bucket_start": _clip(row.get("bucket_start", ""), 80),
        "component": _clip(row.get("component", "unknown"), 220),
        "operation": _clip(row.get("operation", "unknown"), 260),
        "hits": int(row.get("hits", 0) or 0),
        "qps": float(row.get("qps", 0.0) or 0.0),
        "p95_latency_ms": row.get("p95_latency_ms"),
    }


def _heatmap_facts(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для тепловой карты, фактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Компактный словарь фактов для выбранного профиля агентского этапа.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    profile_result = context.profile_result
    if profile_result is None:
        raise RuntimeError("Profile computation must run before agent facts.")
    payload = profile_result.payload
    findings = _dict(payload.get("findings"))
    hotspots = findings.get("hottest_buckets") or payload.get("rows") or []
    return {
        "profile": "heatmap",
        "summary": _scalars(_dict(profile_result.summary)),
        "hotspots": [_hotspot(_dict(row)) for row in _take(hotspots, MAX_HEATMAP_CARDS)],
        "findings": {
            "top_components": _counter_items(findings.get("top_components")),
            "top_operations": _counter_items(findings.get("top_operations")),
            "top_status_codes": _counter_items(findings.get("top_status_codes")),
            "top_client_ips": _counter_items(findings.get("top_client_ips")),
            "suspicious_ip_bursts": [
                {
                    "bucket_start": _clip(_dict(item).get("bucket_start", ""), 80),
                    "client_ip": _clip(_dict(item).get("client_ip", ""), 120),
                    "hits": _dict(item).get("hits", 0),
                    "reason": _clip(_dict(item).get("reason", ""), 160),
                }
                for item in _take(findings.get("suspicious_ip_bursts"), 5)
            ],
            "llm_ready_summary": _dict(findings.get("llm_ready_summary")),
        },
    }


def _traffic_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для трафика, строки.
    
    Args:
        row (Dict[str, Any]): Одна строка табличных данных, из которой строится объект результата.
    
    Returns:
        Dict[str, Any]: Компактное описание строки трафика с методом, путем, статусом, частотой, ошибками и p95 задержки.
    """
    return {
        "method": _clip(row.get("method", "UNKNOWN"), 32),
        "path": _clip(row.get("path", "unknown"), 260),
        "http_status": row.get("http_status"),
        "hits": int(row.get("hits", 0) or 0),
        "unique_ips": int(row.get("unique_ips", 0) or 0),
        "p95_latency_ms": row.get("p95_latency_ms"),
        "p99_latency_ms": row.get("p99_latency_ms"),
        "avg_response_size": row.get("avg_response_size"),
    }


def _traffic_anomaly(row: Dict[str, Any]) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для трафика.
    
    Args:
        row (Dict[str, Any]): Одна строка табличных данных, из которой строится объект результата.
    
    Returns:
        Dict[str, Any]: Компактное описание аномалии трафика с типом паттерна, серьезностью, причиной и связанными HTTP/IP-полями.
    """
    payload = _dict(row.get("payload"))
    return {
        "anomaly_type": _clip(row.get("anomaly_type", ""), 80),
        "severity": _clip(row.get("severity", "medium"), 40),
        "title": _clip(row.get("title", ""), 240),
        "details": _clip(row.get("details", ""), 320),
        "payload": {
            key: (_clip(value, 260) if isinstance(value, str) else value)
            for key, value in payload.items()
            if key in {"method", "path", "http_status", "hits", "unique_ips", "p95_latency_ms", "client_ip", "request_count"}
        },
    }


def _traffic_facts(context: PipelineContext) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для трафика, фактов.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Компактный словарь фактов для выбранного профиля агентского этапа.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    profile_result = context.profile_result
    if profile_result is None:
        raise RuntimeError("Profile computation must run before agent facts.")
    payload = profile_result.payload
    rows = [_traffic_row(_dict(row)) for row in payload.get("rows", [])]
    anomalies = [_traffic_anomaly(_dict(row)) for row in payload.get("anomalies", [])]
    slow_rows = sorted(rows, key=lambda row: row.get("p95_latency_ms") or 0, reverse=True)
    error_rows = [
        row for row in rows
        if row.get("http_status") is not None and int(row.get("http_status") or 0) >= 500
    ]
    return {
        "profile": "traffic",
        "summary": _scalars(_dict(profile_result.summary)),
        "traffic_findings": {
            "top_endpoints_by_hits": rows[:MAX_TRAFFIC_CARDS],
            "slow_endpoints": slow_rows[:MAX_AGENT_LIST_ITEMS],
            "server_error_endpoints": error_rows[:MAX_AGENT_LIST_ITEMS],
        },
        "suspicious_patterns": anomalies[:MAX_TRAFFIC_CARDS],
        "latency_load_summary": {
            "endpoint_count": len(rows),
            "anomaly_count": len(anomalies),
            "max_hits": max((row["hits"] for row in rows), default=0),
            "max_p95_latency_ms": max((row.get("p95_latency_ms") or 0 for row in rows), default=0),
        },
    }


def build_agent_input_context(context: PipelineContext) -> PipelineContext:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: агентского этапа.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Контекст конвейера с результатами выполненного этапа и обновленными промежуточными данными.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
        ValueError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if context.profile_result is None:
        raise RuntimeError("Profile computation must run before agent input context.")
    if context.run_summary is None:
        raise RuntimeError("Run summary must be built before agent input context.")

    started = time.perf_counter()
    profile = context.config.profile
    if profile == "incidents":
        facts = _incidents_facts(context)
    elif profile == "heatmap":
        facts = _heatmap_facts(context)
    elif profile == "traffic":
        facts = _traffic_facts(context)
    else:
        raise ValueError(f"Unsupported profile for agent input context: {profile}")

    context.agent_input_context = AgentInputContext(
        profile=profile,
        run_id=context.run_id,
        run_summary=_run_summary(context),
        parser_diagnostics=_parser_diagnostics(context),
        profile_fit=_profile_fit(context),
        facts=facts,
        limits=dict(AGENT_CONTEXT_LIMITS),
        requested_focus=context.config.agent_question,
    )
    context.timings["agent_input_context"] = time.perf_counter() - started
    serialized_chars = len(json.dumps(context.agent_input_context.as_dict(), ensure_ascii=False))
    facts_shape: Dict[str, Any] = {"facts_keys": sorted(facts.keys())}
    if profile == "incidents":
        facts_shape["cluster_facts"] = len(facts.get("compact_llm_ready_cluster_facts", []))
        facts_shape["cluster_candidates"] = len(facts.get("top_cluster_candidates", []))
    elif profile == "heatmap":
        facts_shape["hotspots"] = len(facts.get("hotspots", []))
    elif profile == "traffic":
        traffic_findings = _dict(facts.get("traffic_findings"))
        facts_shape["traffic_rows"] = len(traffic_findings.get("top_endpoints_by_hits", []))
        facts_shape["suspicious_patterns"] = len(facts.get("suspicious_patterns", []))
    logger.info(
        "agent_input_context_built: run_id=%s profile=%s chars=%d duration=%.3fs shape=%s",
        context.run_id,
        profile,
        serialized_chars,
        context.timings["agent_input_context"],
        facts_shape,
    )
    return context


__all__ = ["build_agent_input_context"]
