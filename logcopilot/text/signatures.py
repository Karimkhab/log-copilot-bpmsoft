from __future__ import annotations

"""Построители сигнатур и текстов для эмбеддингов по событиям логов."""

import hashlib
import re
from typing import List, Optional

from ..domain import Event, RawEvent
from .normalization import NormalizationStats, normalize_text

EXCEPTION_RE = re.compile(r"\b([A-Za-z_][\w.]+(?:Exception|Error))\b")
STACK_FRAME_RE = re.compile(r"^\s*at\s+(.+?)(?:\(|\s+in\s+|$)")
INCIDENT_KEYWORD_RE = re.compile(
    r"\b(exception|error|failed|failure|fatal|timeout|timed out|refused|denied|unavailable|panic|crash|terminated|killed)\b",
    re.IGNORECASE,
)


def extract_exception_type(*chunks: str) -> Optional[str]:
    """Извлекает из входных данных значимые признаки или идентификаторы.
    
    Args:
        *chunks (str): Значение `chunks`, используемое функцией при выполнении операции.
    
    Returns:
        Optional[str]: Имя первого найденного класса исключения или ошибки; None, если такие признаки отсутствуют.
    """
    for chunk in chunks:
        if not chunk:
            continue
        match = EXCEPTION_RE.search(chunk)
        if match:
            return match.group(1)
    return None


def extract_stack_frames(stacktrace: str, top_n: int = 3) -> List[str]:
    """Извлекает из входных данных значимые признаки или идентификаторы.
    
    Args:
        stacktrace (str): Значение `stacktrace`, используемое функцией при выполнении операции.
        top_n (int, optional): Количество наиболее значимых элементов, которые нужно включить в результат.
    
    Returns:
        List[str]: До `top_n` верхних стек-фреймов, очищенных от лишних пробелов и служебных суффиксов.
    """
    frames: List[str] = []
    for line in (stacktrace or "").splitlines():
        match = STACK_FRAME_RE.match(line)
        if not match:
            continue
        frame = re.sub(r"\s+", " ", match.group(1)).strip()
        frame = re.sub(r"`\d+", "", frame)
        frames.append(frame)
        if len(frames) >= top_n:
            break
    return frames


def build_signature(
    normalized_message: str,
    exception_type: Optional[str],
    stack_frames: List[str],
) -> str:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        normalized_message (str): Значение `normalized_message`, используемое функцией при выполнении операции.
        exception_type (Optional[str]): Значение `exception_type`, используемое функцией при выполнении операции.
        stack_frames (List[str]): Значение `stack_frames`, используемое функцией при выполнении операции.
    
    Returns:
        str: SHA1-хеш сигнатуры, построенный из нормализованного сообщения, типа исключения и верхних stack frames.
    """
    payload = "||".join(
        [normalized_message or "", exception_type or "", *stack_frames]
    ).encode("utf-8", errors="ignore")
    return hashlib.sha1(payload).hexdigest()


def is_incident_candidate(event: RawEvent, exception_type: Optional[str]) -> bool:
    """Проверяет условие и возвращает логический результат. Область применения: инцидента.
    
    Args:
        event (RawEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        exception_type (Optional[str]): Значение `exception_type`, используемое функцией при выполнении операции.
    
    Returns:
        bool: True, если событие похоже на инцидент по уровню, исключению, stacktrace, HTTP 5xx или ключевым словам.
    """
    level = (event.level or "").upper()
    if level in {"ERROR", "FATAL"}:
        return True
    if exception_type:
        return True
    if event.stacktrace.strip():
        return True
    if event.http_status is not None and event.http_status >= 500:
        return True
    if level in {"WARN", "WARNING"} and INCIDENT_KEYWORD_RE.search(event.message):
        return True
    return bool(INCIDENT_KEYWORD_RE.search(event.message) or INCIDENT_KEYWORD_RE.search(event.raw_text))


def make_event_signature(
    event: RawEvent, normalization_stats: Optional[NormalizationStats] = None
) -> tuple[str, Optional[str], List[str], bool]:
    """Создает значение на основе входных данных и возвращает его вызывающему коду. Область применения: события.
    
    Args:
        event (RawEvent): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
        normalization_stats (Optional[NormalizationStats], optional): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        tuple[str, Optional[str], List[str], bool]: Нормализованное сообщение, тип исключения, верхние stack frames и признак инцидента.
    """
    normalized_message = normalize_text(event.message, normalization_stats)
    exception_type = extract_exception_type(event.stacktrace, event.message)
    stack_frames = extract_stack_frames(event.stacktrace)
    is_incident = is_incident_candidate(event, exception_type)
    return normalized_message, exception_type, stack_frames, is_incident


def build_embedding_text(event: Event) -> str:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        event (Event): Событие лога, которое нужно преобразовать, оценить или добавить в агрегатор.
    
    Returns:
        str: Текст для эмбеддинга с профилем парсера, уровнем, компонентом, сообщением и важными техническими признаками.
    """
    parts = [
        f"profile={event.parser_profile}",
        f"level={(event.level or 'unknown').lower()}",
        f"component={event.component or 'unknown'}",
        f"message={event.normalized_message or normalize_text(event.message)}",
    ]
    if event.exception_type:
        parts.append(f"exception={event.exception_type}")
    if event.stack_frames:
        parts.append("stack=" + " | ".join(event.stack_frames))
    elif event.stacktrace.strip():
        parts.append("stack=" + normalize_text(event.stacktrace))
    if event.http_status is not None:
        parts.append(f"http_status={event.http_status}")
    if event.request_id:
        parts.append("has_request_id=true")
    if event.trace_id:
        parts.append("has_trace_id=true")
    raw_fallback = normalize_text(event.raw_text) if event.raw_text else ""
    if raw_fallback and raw_fallback not in " ".join(parts):
        parts.append(f"raw={raw_fallback}")
    return " || ".join(part for part in parts if part)


def build_signature_text(
    normalized_message: str,
    exception_type: Optional[str],
    stack_frames: List[str],
) -> str:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        normalized_message (str): Значение `normalized_message`, используемое функцией при выполнении операции.
        exception_type (Optional[str]): Значение `exception_type`, используемое функцией при выполнении операции.
        stack_frames (List[str]): Значение `stack_frames`, используемое функцией при выполнении операции.
    
    Returns:
        str: Человекочитаемый текст сигнатуры из нормализованного сообщения, исключения и верхних stack frames.
    """
    parts = [f"normalized_message={normalized_message}"]
    if exception_type:
        parts.append(f"exception_type={exception_type}")
    if stack_frames:
        parts.append("top_stack_frames=" + " | ".join(stack_frames))
    return " || ".join(parts)
