from __future__ import annotations

"""Профиль трафика: сводки эндпоинтов, отчеты по задержкам и поиск аномалий."""

from collections import Counter, defaultdict
from statistics import mean, quantiles
from typing import Iterable, List, Optional

from ..domain import Event


def _collect_client_ip_activity(events: List[Event]) -> tuple[defaultdict[str, set[str]], Counter[str]]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        tuple[defaultdict[str, set[str]], Counter[str]]: Карта путей по клиентским IP и счетчик запросов по IP.
    """
    path_by_ip = defaultdict(set)
    hits_by_ip: Counter[str] = Counter()
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        if not event.client_ip:
            continue
        hits_by_ip[event.client_ip] += 1
        if event.path:
            path_by_ip[event.client_ip].add(event.path)
    return path_by_ip, hits_by_ip


def _build_row_anomalies(rows: List[dict]) -> List[dict]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: строки.
    
    Args:
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
    
    Returns:
        List[dict]: Аномалии по агрегированным строкам трафика: ошибки, высокая задержка и повышенная нагрузка.
    """
    anomalies = []
    for row in rows:
        status = row["http_status"]
        if status is not None and status >= 500 and row["hits"] >= 1:
            anomalies.append(
                {
                    "anomaly_type": "server_errors",
                    "severity": "high" if row["hits"] >= 3 else "medium",
                    "title": f"5xx traffic on {row['method']} {row['path']}",
                    "details": f"{row['hits']} requests returned {status}",
                    "payload": row,
                }
            )
        if (row["p95_latency_ms"] or 0) >= 1000:
            anomalies.append(
                {
                    "anomaly_type": "latency",
                    "severity": "medium",
                    "title": f"Slow endpoint {row['method']} {row['path']}",
                    "details": f"p95 latency is {row['p95_latency_ms']} ms",
                    "payload": row,
                }
            )
    return anomalies


def _build_scan_like_anomalies(
    path_by_ip: defaultdict[str, set[str]],
    hits_by_ip: Counter[str],
) -> List[dict]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        path_by_ip (defaultdict[str, set[str]]): Значение `path_by_ip`, используемое функцией при выполнении операции.
        hits_by_ip (Counter[str]): Значение `hits_by_ip`, используемое функцией при выполнении операции.
    
    Returns:
        List[dict]: Подозрительные IP, похожие на сканирование, с количеством запросов и уникальных путей.
    """
    anomalies = []
    for client_ip, unique_paths in path_by_ip.items():
        if len(unique_paths) >= 10 or hits_by_ip[client_ip] >= 20:
            anomalies.append(
                {
                    "anomaly_type": "scan_like",
                    "severity": "high",
                    "title": f"Potential scanning from {client_ip}",
                    "details": f"{hits_by_ip[client_ip]} requests across {len(unique_paths)} paths",
                    "payload": {
                        "client_ip": client_ip,
                        "request_count": hits_by_ip[client_ip],
                        "unique_paths": len(unique_paths),
                    },
                }
            )
    return anomalies


def percentile(values: List[float], rank: int) -> Optional[float]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        values (List[float]): Набор входных значений, используемых при вычислении результата.
        rank (int): Процентиль или ранг, который нужно вычислить по набору значений.
    
    Returns:
        Optional[float]: Значение указанного перцентиля или None, если входной список пуст.
    """
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 3)
    return round(quantiles(values, n=100, method="inclusive")[rank - 1], 3)


def build_traffic_rows(events: Iterable[Event]) -> List[dict]:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: трафика, строк.
    
    Args:
        events (Iterable[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        List[dict]: Агрегированные строки трафика по методу, пути и статусу с частотой, ошибками и p95 задержки.
    """
    grouped = defaultdict(list)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        key = (event.method or "UNKNOWN", event.path or "unknown", event.http_status)
        grouped[key].append(event)

    rows = []
    for (method, path, http_status), bucket_events in grouped.items():
        latencies = [event.latency_ms for event in bucket_events if event.latency_ms is not None]
        sizes = [event.response_size for event in bucket_events if event.response_size is not None]
        unique_ips = {event.client_ip for event in bucket_events if event.client_ip}
        rows.append(
            {
                "method": method,
                "path": path,
                "http_status": http_status,
                "hits": len(bucket_events),
                "unique_ips": len(unique_ips),
                "p95_latency_ms": percentile(latencies, 95),
                "p99_latency_ms": percentile(latencies, 99),
                "avg_response_size": round(mean(sizes), 3) if sizes else None,
            }
        )
    rows.sort(key=lambda item: (item["hits"], item["p95_latency_ms"] or 0), reverse=True)
    return rows


def build_traffic_anomalies(events: List[Event], rows: List[dict]) -> List[dict]:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: трафика.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        rows (List[dict]): Строки табличных данных, которые нужно записать, агрегировать или проверить.
    
    Returns:
        List[dict]: Объединенный список аномалий трафика по строкам и подозрительной активности IP.
    """
    path_by_ip, hits_by_ip = _collect_client_ip_activity(events)
    anomalies = _build_row_anomalies(rows)
    anomalies.extend(_build_scan_like_anomalies(path_by_ip, hits_by_ip))
    return anomalies


def run_traffic_profile(events: List[Event], output_dir) -> dict:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: трафика, профиля.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        output_dir (Any): Директория, в которой создаются артефакты текущего запуска.
    
    Returns:
        dict: Полезная нагрузка профиля трафика: summary, строки latency/load, suspicious_patterns и analysis_summary.
    """
    del output_dir
    rows = build_traffic_rows(events)
    anomalies = build_traffic_anomalies(events, rows)

    return {
        "rows": rows,
        "anomalies": anomalies,
        "artifact_paths": {},
        "summary": {
            "traffic_row_count": len(rows),
            "anomaly_count": len(anomalies),
        },
    }
