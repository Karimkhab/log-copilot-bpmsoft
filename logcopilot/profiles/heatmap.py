from __future__ import annotations

"""Профиль тепловой карты: поминутные горячие точки и операционные выводы."""

import re
from collections import Counter, defaultdict
from datetime import datetime
from statistics import quantiles
from typing import Iterable, List
from urllib.parse import urlsplit

from ..domain import Event


_PATH_ID_RE = re.compile(r"/(?:(?:\d+)|(?:[0-9a-fA-F]{8,})|(?:[0-9a-fA-F-]{8,}))(?:/|$)")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_text(value: str | None) -> str:
    """Нормализует входное значение к каноническому виду, удобному для сравнения и агрегации.
    
    Args:
        value (str | None): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        str: Очищенная строка для группировки тепловой карты; `unknown`, если значение пустое.
    """
    if not value:
        return "unknown"
    normalized = _WHITESPACE_RE.sub(" ", value).strip()
    return normalized[:120] if normalized else "unknown"


def normalize_path(path: str | None) -> str | None:
    """Нормализует входное значение к каноническому виду, удобному для сравнения и агрегации. Область применения: пути.
    
    Args:
        path (str | None): Путь к файлу или артефакту, с которым работает функция.
    
    Returns:
        str | None: Нормализованный HTTP-путь без query-string и завершающего слеша; None, если пути нет.
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


def top_counter_items(counter: Counter, limit: int = 10) -> List[dict]:
    """Возвращает наиболее значимые элементы по частоте, весу или другому критерию.
    
    Args:
        counter (Counter): Счетчик частот, из которого выбираются наиболее частые элементы.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[dict]: Список самых частых элементов счетчика в виде словарей с `value` и `count`.
    """
    return [{"value": value, "hits": hits} for value, hits in counter.most_common(limit)]


def minute_bucket(timestamp: datetime | None) -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        timestamp (datetime | None): Значение `timestamp`, используемое функцией при выполнении операции.
    
    Returns:
        str: ISO-строка начала минутного бакета или `unknown`, если временная метка отсутствует.
    """
    if timestamp is None:
        return "unknown"
    return timestamp.replace(second=0, microsecond=0).isoformat(sep=" ")


def percentile_95(values: List[float]) -> float | None:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        values (List[float]): Набор входных значений, используемых при вычислении результата.
    
    Returns:
        float | None: Приближенный 95-й перцентиль значений; None для пустого списка.
    """
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 3)
    return round(quantiles(values, n=100, method="inclusive")[94], 3)


def derive_operation(event: Event) -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        event (Event): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
    
    Returns:
        str: Операция события для агрегирования: компонент, HTTP-метод с путем или fallback-источник.
    """
    normalized_path = normalize_path(event.path)
    if normalized_path:
        method = normalize_text(event.method).upper() if getattr(event, "method", None) else None
        return f"{method} {normalized_path}" if method else normalized_path
    if event.message:
        message_head = event.message.split(" - ", 1)[0]
        return normalize_text(message_head)
    if event.component:
        return normalize_text(event.component)
    return "unknown"


def build_heatmap_rows(events: Iterable[Event]) -> List[dict]:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: тепловой карты, строк.
    
    Args:
        events (Iterable[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        List[dict]: Поминутные строки тепловой карты с количеством событий, ошибками, статусами, компонентами и задержками.
    """
    grouped = defaultdict(list)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        bucket = minute_bucket(event.timestamp)
        component = normalize_text(event.component)
        operation = derive_operation(event)
        if bucket == "unknown" and component == "unknown" and operation == "unknown":
            continue
        key = (bucket, component, operation)
        grouped[key].append(event)

    rows = []
    for (bucket_start, component, operation), bucket_events in grouped.items():
        latencies = [event.latency_ms for event in bucket_events if event.latency_ms is not None]
        hits = len(bucket_events)
        rows.append(
            {
                "bucket_start": bucket_start,
                "component": component,
                "operation": operation,
                "hits": hits,
                "qps": round(hits / 60.0, 3),
                "p95_latency_ms": percentile_95(latencies),
            }
        )
    rows.sort(key=lambda item: (item["hits"], item["p95_latency_ms"] or 0), reverse=True)
    return rows


def _build_ip_bursts(events: Iterable[Event]) -> List[dict]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        events (Iterable[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        List[dict]: Сводка активности IP-адресов по минутам с количеством событий и разнообразием путей.
    """
    per_ip_bucket = defaultdict(int)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        ip = getattr(event, "client_ip", None)
        if not ip:
            continue
        bucket = minute_bucket(event.timestamp)
        per_ip_bucket[(bucket, ip)] += 1
    return [
        {"bucket_start": bucket, "client_ip": ip, "hits": hits}
        for (bucket, ip), hits in sorted(per_ip_bucket.items(), key=lambda item: item[1], reverse=True)
    ]


def _build_suspicious_ip_bursts(ip_bursts: List[dict], limit: int = 10) -> List[dict]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        ip_bursts (List[dict]): Значение `ip_bursts`, используемое функцией при выполнении операции.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[dict]: Подозрительные всплески IP-активности, отсортированные по числу событий и разнообразию путей.
    """
    suspicious = []
    for item in ip_bursts:
        if item["hits"] >= 20:
            suspicious.append({**item, "reason": "high_requests_per_minute"})
        if len(suspicious) >= limit:
            break
    return suspicious


def _build_hottest_buckets(rows: List[dict], limit: int = 10) -> List[dict]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[dict]: Самые нагруженные минутные бакеты с ошибками, задержками и основными компонентами.
    """
    return [
        {
            "bucket_start": row["bucket_start"],
            "component": row["component"],
            "operation": row["operation"],
            "hits": row["hits"],
            "qps": row["qps"],
            "p95_latency_ms": row["p95_latency_ms"],
        }
        for row in rows[:limit]
    ]


def build_heatmap_findings(events: List[Event], rows: List[dict]) -> dict:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: тепловой карты.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
    
    Returns:
        dict: Выводы тепловой карты: горячие интервалы, подозрительные IP-всплески и общие счетчики.
    """
    component_counts = Counter(normalize_text(event.component) for event in events)
    operation_counts = Counter(derive_operation(event) for event in events)
    status_counts = Counter(
        str(status)
        for status in (getattr(event, "http_status", None) for event in events)
        if status is not None
    )
    ip_counts = Counter(ip for ip in (getattr(event, "client_ip", None) for event in events) if ip)
    ip_bursts = _build_ip_bursts(events)
    suspicious_ip_bursts = _build_suspicious_ip_bursts(ip_bursts)
    hottest_buckets = _build_hottest_buckets(rows)

    return {
        "profile": "heatmap",
        "total_events": len(events),
        "bucket_count": len(rows),
        "top_components": top_counter_items(component_counts),
        "top_operations": top_counter_items(operation_counts),
        "top_status_codes": top_counter_items(status_counts),
        "top_client_ips": top_counter_items(ip_counts),
        "top_ip_bursts": ip_bursts[:20],
        "suspicious_ip_bursts": suspicious_ip_bursts,
        "hottest_buckets": hottest_buckets,
        "llm_ready_summary": {
            "peak_load_bucket": hottest_buckets[0] if hottest_buckets else None,
            "most_active_ip": top_counter_items(ip_counts, limit=1)[0] if ip_counts else None,
            "largest_ip_burst": ip_bursts[0] if ip_bursts else None,
            "dominant_component": top_counter_items(component_counts, limit=1)[0] if component_counts else None,
            "dominant_operation": top_counter_items(operation_counts, limit=1)[0] if operation_counts else None,
        },
    }


def run_heatmap_profile(events: List[Event], output_dir) -> dict:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: тепловой карты, профиля.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        output_dir (Any): Директория, в которой создаются артефакты текущего запуска.
    
    Returns:
        dict: Полезная нагрузка профиля тепловой карты со строками timeseries, выводами, сводкой и analysis_summary.
    """
    del output_dir
    rows = build_heatmap_rows(events)
    findings = build_heatmap_findings(events, rows)

    return {
        "rows": rows,
        "findings": findings,
        "artifact_paths": {},
        "summary": {
            "bucket_count": len(rows),
            "hottest_bucket": rows[0] if rows else None,
            "llm_ready_summary": findings["llm_ready_summary"],
        },
    }
