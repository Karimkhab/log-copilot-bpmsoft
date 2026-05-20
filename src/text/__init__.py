from __future__ import annotations

"""Вспомогательные средства обработки текста: нормализация и построение сигнатур."""

from .normalization import NormalizationStats, count_mask_tokens, normalize_text
from .signatures import (
    build_embedding_text,
    build_signature,
    build_signature_text,
    extract_exception_type,
    extract_stack_frames,
    is_incident_candidate,
    make_event_signature,
)

__all__ = [
    "NormalizationStats",
    "build_embedding_text",
    "build_signature",
    "build_signature_text",
    "count_mask_tokens",
    "extract_exception_type",
    "extract_stack_frames",
    "is_incident_candidate",
    "make_event_signature",
    "normalize_text",
]
