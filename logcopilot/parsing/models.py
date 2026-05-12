from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class CanonicalEvent:
    """Каноническое представление, создаваемое подсистемой парсинга."""

    timestamp: Optional[datetime]
    level: Optional[str]
    source: Optional[str]
    component: Optional[str]
    message: str
    raw_text: str
    stacktrace: str = ""
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    latency_ms: Optional[float] = None
    response_size: Optional[int] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    parser_name: str = "unknown"
    parser_confidence: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    line_count: int = 1


@dataclass
class ParseResult:
    """Структурированный результат реализации парсера."""

    events: List[CanonicalEvent]
    parser_name: str
    confidence: float
    stats: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ParserSelection:
    """Результат выбора парсера на основе детектора."""

    parser_name: str
    confidence: float
    used_fallback: bool = False

