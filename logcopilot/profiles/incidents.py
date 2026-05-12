from __future__ import annotations

"""Профиль инцидентов: кластеризация по сигнатурам и семантическая группировка."""

from dataclasses import asdict
import logging
from pathlib import Path
from typing import Callable, List, Optional

from ..analysis import (
    AnalysisQualityAccumulator,
    ClusterAccumulator,
    cluster_signatures_semantically,
    top_incident_clusters,
)
from ..domain import AnalysisSummary, Event
logger = logging.getLogger(__name__)


def build_quality_summary(events: List[Event], source_name: str, cluster_count: int) -> AnalysisSummary:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: качества, сводки.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        source_name (str): Человекочитаемое имя источника, используемое в сводках качества.
        cluster_count (int): Количество найденных кластеров, учитываемое в итоговой сводке.
    
    Returns:
        AnalysisSummary: Сводка качества профиля инцидентов с учетом событий, источника и количества кластеров.
    """
    quality = AnalysisQualityAccumulator(source_name=source_name)
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        quality.add(event)
    return quality.build_summary(cluster_count=cluster_count)


def run_incidents_profile(
    events: List[Event],
    output_dir: Path,
    source_name: str,
    semantic: str = "on",
    semantic_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    semantic_min_cluster_size: int = 3,
    semantic_min_samples: Optional[int] = None,
    semantic_cache_dir: Optional[Path] = None,
    semantic_max_signatures: int = 2500,
    progress_callback: Callable[[str], None] | None = None,
) -> dict:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы. Область применения: инцидентов, профиля.
    
    Args:
        events (List[Event]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        output_dir (Path): Директория, в которой создаются артефакты текущего запуска.
        source_name (str): Человекочитаемое имя источника, используемое в сводках качества.
        semantic (str, optional): Значение `semantic`, используемое функцией при выполнении операции.
        semantic_model (str, optional): Значение `semantic_model`, используемое функцией при выполнении операции.
        semantic_min_cluster_size (int, optional): Значение `semantic_min_cluster_size`, используемое функцией при выполнении операции.
        semantic_min_samples (Optional[int], optional): Значение `semantic_min_samples`, используемое функцией при выполнении операции.
        semantic_cache_dir (Optional[Path], optional): Директория кэша, где хранятся эмбеддинги и вспомогательные файлы.
        semantic_max_signatures (int, optional): Значение `semantic_max_signatures`, используемое функцией при выполнении операции.
        progress_callback (Callable[[str], None] | None, optional): Значение `progress_callback`, используемое функцией при выполнении операции.
    
    Returns:
        dict: Полезная нагрузка профиля инцидентов: кластеры, top-кластеры, семантические группы, summary и analysis_summary.
    """
    del output_dir
    accumulator = ClusterAccumulator()
    # Проходим события один раз и одновременно накапливаем агрегаты для отчета.
    for event in events:
        accumulator.add(event)

    clusters = accumulator.build_summaries()
    top_clusters = top_incident_clusters(clusters, limit=10)
    logger.info(
        "incidents_clusters_built: events=%d clusters=%d top_clusters=%d",
        len(events),
        len(clusters),
        len(top_clusters),
    )
    analysis_summary = build_quality_summary(events, source_name=source_name, cluster_count=len(clusters))
    semantic_clusters, semantic_note = cluster_signatures_semantically(
        events=accumulator.representatives(),
        enabled=semantic,
        model_name=semantic_model,
        min_cluster_size=semantic_min_cluster_size,
        min_samples=semantic_min_samples,
        cache_dir=semantic_cache_dir,
        max_signatures=semantic_max_signatures,
        progress_callback=progress_callback,
    )
    logger.info(
        "incidents_semantic_stage: semantic_clusters=%d note=%s",
        len(semantic_clusters),
        semantic_note,
    )

    return {
        "clusters": clusters,
        "top_clusters": top_clusters,
        "semantic_clusters": semantic_clusters,
        "analysis_summary": analysis_summary,
        "semantic_note": semantic_note,
        "artifact_paths": {},
        "summary": {
            "cluster_count": len(clusters),
            "semantic_cluster_count": len(semantic_clusters),
            "incident_event_count": analysis_summary.incident_event_count,
            "semantic_note": semantic_note,
            "analysis_summary": asdict(analysis_summary),
        },
    }
