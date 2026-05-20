from __future__ import annotations

"""Вспомогательные функции кластеризации по сигнатурам для анализа инцидентов."""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional

from ..domain import ClusterSummary, Event
from ..text import build_signature_text
from .quality import confidence_label


def choose_first_non_null(values: Iterable[Optional[str]]) -> Optional[str]:
    """Выбирает подходящее значение из набора кандидатов.
    
    Args:
        values (Iterable[Optional[str]]): Набор входных значений, используемых при вычислении результата.
    
    Returns:
        Optional[str]: Первое непустое строковое значение из последовательности; None, если подходящих значений нет.
    """
    for value in values:
        if value:
            return value
    return None


def top_source_files(events: List[Event], limit: int = 5) -> str:
    """Возвращает наиболее значимые элементы по частоте, весу или другому критерию. Область применения: файлов.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        str: Строка со списком самых частых файлов-источников и количеством событий по каждому файлу.
    """
    counts = Counter(event.source_file for event in events)
    return "; ".join(f"{source} ({hits})" for source, hits in counts.most_common(limit))


def sample_messages(events: List[Event], limit: int = 5) -> str:
    """Выполняет вспомогательную операцию для сообщений.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        str: Несколько уникальных примеров сообщений, объединенных разделителем ` || ` для компактного отчета.
    """
    samples: List[str] = []
    seen = set()
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        message = event.message.strip()
        if not message or message in seen:
            continue
        seen.add(message)
        samples.append(message)
        if len(samples) >= limit:
            break
    return " || ".join(samples)


def levels_summary(events: List[Event]) -> str:
    """Выполняет вспомогательную операцию для сводки.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        str: Сводка уровней логирования в формате `LEVEL:count`, отсортированная по частоте.
    """
    counts = Counter((event.level or "UNKNOWN").upper() for event in events)
    return ", ".join(f"{level}:{hits}" for level, hits in counts.most_common())


def min_timestamp(events: List[Event]) -> Optional[datetime]:
    """Выполняет вспомогательную операцию для временной метки.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        Optional[datetime]: Самая ранняя временная метка среди событий; None, если у событий нет времени.
    """
    values = [event.timestamp for event in events if event.timestamp]
    return min(values) if values else None


def max_timestamp(events: List[Event]) -> Optional[datetime]:
    """Выполняет вспомогательную операцию для временной метки.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        Optional[datetime]: Самая поздняя временная метка среди событий; None, если у событий нет времени.
    """
    values = [event.timestamp for event in events if event.timestamp]
    return max(values) if values else None


def build_cluster_summaries(events: List[Event]) -> List[ClusterSummary]:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: кластера.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
    
    Returns:
        List[ClusterSummary]: Список кластеров, сгруппированных по сигнатуре и отсортированных по силе инцидентного сигнала.
    """
    grouped: Dict[str, List[Event]] = defaultdict(list)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        grouped[event.signature_hash].append(event)

    clusters: List[ClusterSummary] = []
    for signature_hash, cluster_events in grouped.items():
        incident_hits = sum(1 for event in cluster_events if event.is_incident)
        clusters.append(
            ClusterSummary(
                cluster_id=signature_hash,
                hits=len(cluster_events),
                first_seen=min_timestamp(cluster_events),
                last_seen=max_timestamp(cluster_events),
                parser_profiles="; ".join(
                    f"{profile} ({hits})"
                    for profile, hits in Counter(
                        event.parser_profile for event in cluster_events
                    ).most_common(3)
                ),
                source_files=top_source_files(cluster_events),
                sample_messages=sample_messages(cluster_events),
                example_exception=choose_first_non_null(
                    event.exception_type for event in cluster_events
                ),
                levels=levels_summary(cluster_events),
                incident_hits=incident_hits,
                representative_raw=cluster_events[0].raw_text[:1000],
                representative_normalized=cluster_events[0].normalized_message,
                representative_signature_text="",
                top_stack_frames=" | ".join(cluster_events[0].stack_frames),
            )
        )
    clusters.sort(
        key=lambda item: (
            item.incident_hits,
            item.hits,
            item.last_seen or datetime.min,
        ),
        reverse=True,
    )
    return clusters


def top_incident_clusters(clusters: List[ClusterSummary], limit: int = 10) -> List[ClusterSummary]:
    """Возвращает наиболее значимые элементы по частоте, весу или другому критерию. Область применения: инцидента, кластеров.
    
    Args:
        clusters (List[ClusterSummary]): Список кластеров событий, используемый для отчетов или сохранения.
        limit (int, optional): Максимальное количество элементов или символов, которые нужно вернуть или сохранить.
    
    Returns:
        List[ClusterSummary]: До `limit` кластеров с инцидентными событиями; если таких нет, возвращаются самые крупные кластеры.
    """
    incident_clusters = [cluster for cluster in clusters if cluster.incident_hits > 0]
    if incident_clusters:
        return incident_clusters[:limit]
    return clusters[:limit]


def _pick_representative_event(
    signature_hash: str,
    bucket: Dict[str, object],
    representatives: Dict[str, Event],
) -> Event | None:
    """Выполняет вспомогательную операцию для события.
    
    Args:
        signature_hash (str): Значение `signature_hash`, используемое функцией при выполнении операции.
        bucket (Dict[str, object]): Значение `bucket`, используемое функцией при выполнении операции.
        representatives (Dict[str, Event]): Значение `representatives`, используемое функцией при выполнении операции.
    
    Returns:
        Event | None: Представительное событие кластера из bucket или резервного словаря representatives; None, если события нет.
    """
    return bucket["representative_event"] or representatives.get(signature_hash)


def _build_cluster_summary(
    signature_hash: str,
    bucket: Dict[str, object],
    representative_event: Event | None,
) -> ClusterSummary:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: кластера, сводки.
    
    Args:
        signature_hash (str): Значение `signature_hash`, используемое функцией при выполнении операции.
        bucket (Dict[str, object]): Значение `bucket`, используемое функцией при выполнении операции.
        representative_event (Event | None): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
    
    Returns:
        ClusterSummary: Готовая сводка одного кластера с количеством событий, временем, источниками, уровнями и примером сообщения.
    """
    source_counts = bucket["source_counts"]
    level_counts = bucket["level_counts"]
    profile_counts = bucket["profile_counts"]
    hits = bucket["hits"]
    confidence_score = _cluster_confidence_score(bucket)
    return ClusterSummary(
        cluster_id=signature_hash,
        hits=hits,
        first_seen=bucket["first_seen"],
        last_seen=bucket["last_seen"],
        parser_profiles="; ".join(
            f"{profile} ({count})"
            for profile, count in profile_counts.most_common(3)
        ),
        source_files="; ".join(
            f"{source} ({hits})"
            for source, hits in source_counts.most_common(5)
        ),
        sample_messages=" || ".join(bucket["sample_messages"]),
        example_exception=bucket["example_exception"],
        levels=", ".join(
            f"{level}:{hits}" for level, hits in level_counts.most_common()
        ),
        incident_hits=bucket["incident_hits"],
        confidence_score=confidence_score,
        confidence_label=confidence_label(confidence_score),
        clustering_method="signature",
        representative_raw=(
            representative_event.raw_text[:2000] if representative_event else ""
        ),
        representative_normalized=(
            representative_event.normalized_message if representative_event else ""
        ),
        representative_signature_text=(
            build_signature_text(
                representative_event.normalized_message,
                representative_event.exception_type,
                representative_event.stack_frames,
            )
            if representative_event
            else ""
        ),
        top_stack_frames=(
            " | ".join(representative_event.stack_frames)
            if representative_event
            else ""
        ),
    )


class ClusterAccumulator:
    """Постепенно накапливает события в статистику кластеров на основе сигнатур."""

    def __init__(self) -> None:
        """Инициализирует объект и сохраняет параметры, необходимые для дальнейшей работы.

        Args:
            Нет параметров.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        self._clusters: Dict[str, Dict[str, object]] = {}
        self._representatives: Dict[str, Event] = {}

    def add(self, event: Event) -> None:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            event (Event): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        bucket = self._clusters.setdefault(
            event.signature_hash,
            {
                "hits": 0,
                "first_seen": None,
                "last_seen": None,
                "source_counts": Counter(),
                "sample_messages": [],
                "sample_seen": set(),
                "example_exception": None,
                "level_counts": Counter(),
                "incident_hits": 0,
                "timestamp_count": 0,
                "component_count": 0,
                "exception_count": 0,
                "stacktrace_count": 0,
                "profile_counts": Counter(),
                "representative_event": None,
            },
        )
        bucket["hits"] += 1
        if event.timestamp:
            bucket["timestamp_count"] += 1
            first_seen = bucket["first_seen"]
            last_seen = bucket["last_seen"]
            bucket["first_seen"] = (
                event.timestamp
                if first_seen is None or event.timestamp < first_seen
                else first_seen
            )
            bucket["last_seen"] = (
                event.timestamp
                if last_seen is None or event.timestamp > last_seen
                else last_seen
            )
        bucket["source_counts"][event.source_file] += 1
        bucket["level_counts"][(event.level or "UNKNOWN").upper()] += 1
        bucket["profile_counts"][event.parser_profile] += 1
        if event.component:
            bucket["component_count"] += 1
        if event.is_incident:
            bucket["incident_hits"] += 1
        if not bucket["example_exception"] and event.exception_type:
            bucket["example_exception"] = event.exception_type
        if event.exception_type:
            bucket["exception_count"] += 1
        if event.stacktrace.strip():
            bucket["stacktrace_count"] += 1
        if event.message.strip() and event.message not in bucket["sample_seen"]:
            bucket["sample_seen"].add(event.message)
            if len(bucket["sample_messages"]) < 5:
                bucket["sample_messages"].append(event.message)

        representative = self._representatives.get(event.signature_hash)
        if representative is None:
            self._representatives[event.signature_hash] = event
            bucket["representative_event"] = event
        elif event.is_incident and not representative.is_incident:
            self._representatives[event.signature_hash] = event
            bucket["representative_event"] = event
        elif len(event.stacktrace) > len(representative.stacktrace):
            self._representatives[event.signature_hash] = event
            bucket["representative_event"] = event

    def representatives(self) -> List[Event]:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            Нет параметров.
        
        Returns:
            List[Event]: Представительные события всех накопленных сигнатурных кластеров.
        """
        return list(self._representatives.values())

    def build_summaries(self) -> List[ClusterSummary]:
        """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки.
        
        Args:
            Нет параметров.
        
        Returns:
            List[ClusterSummary]: Сводки всех накопленных кластеров, отсортированные по incident-сигналу, размеру и времени.
        """
        clusters: List[ClusterSummary] = []
        for signature_hash, bucket in self._clusters.items():
            representative_event = _pick_representative_event(
                signature_hash=signature_hash,
                bucket=bucket,
                representatives=self._representatives,
            )
            clusters.append(
                _build_cluster_summary(
                    signature_hash=signature_hash,
                    bucket=bucket,
                    representative_event=representative_event,
                )
            )
        clusters.sort(
            key=lambda item: (
                item.incident_hits,
                item.hits,
                item.last_seen or datetime.min,
            ),
            reverse=True,
        )
        return clusters


def _cluster_confidence_score(bucket: Dict[str, object]) -> float:
    """Выполняет вспомогательную операцию для кластера, уверенности.
    
    Args:
        bucket (Dict[str, object]): Значение `bucket`, используемое функцией при выполнении операции.
    
    Returns:
        float: Оценка уверенности кластера от 0.0 до 1.0 на основе количества событий и инцидентного сигнала.
    """
    hits = int(bucket["hits"])
    if hits <= 0:
        return 0.0
    incident_ratio = int(bucket["incident_hits"]) / hits
    exception_ratio = int(bucket["exception_count"]) / hits
    stacktrace_ratio = int(bucket["stacktrace_count"]) / hits
    timestamp_ratio = int(bucket["timestamp_count"]) / hits
    component_ratio = int(bucket["component_count"]) / hits
    hit_score = min(1.0, hits / 20.0)
    score = (
        0.3 * incident_ratio
        + 0.25 * exception_ratio
        + 0.15 * stacktrace_ratio
        + 0.15 * timestamp_ratio
        + 0.05 * component_ratio
        + 0.1 * hit_score
    )
    return round(score, 3)
