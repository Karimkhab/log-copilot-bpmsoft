from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any, Mapping, Optional

from .models import CanonicalEvent, ParseResult

LEVEL_ALIASES = {
    "TRACE": "TRACE",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARN": "WARN",
    "WARNING": "WARN",
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "FATAL": "FATAL",
    "CRITICAL": "FATAL",
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S,%f",
    "%Y/%m/%d %H:%M:%S.%f",
    "%y/%m/%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
)

REQUEST_ID_RE = re.compile(r"\brequest[_-]?id\b\s*[:=]?\s*(?P<value>\S+)", re.IGNORECASE)
TRACE_ID_RE = re.compile(
    r"\b(?:trace[_-]?id|correlation[_-]?id|activity[_-]?id|connection[_-]?id)\b\s*[:=]?\s*(?P<value>\S+)",
    re.IGNORECASE,
)
HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", re.IGNORECASE)
HTTP_PATH_RE = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(?P<value>/\S+)", re.IGNORECASE)
STATUS_RE = re.compile(r"\bstatus\s*[:=]?\s*(?P<value>\d{3})\b", re.IGNORECASE)
LATENCY_RE = re.compile(
    r"\b(?:latency|duration|elapsed|elapsed_ms|time|time_ms|request_time)\s*[:=]?\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>ms|s)?\b",
    re.IGNORECASE,
)
SIZE_RE = re.compile(r"\b(?:size|bytes|response_bytes)\s*[:=]?\s*(?P<value>\d+)\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?P<value>(?:\d{1,3}\.){3}\d{1,3})\b")

LOGFMT_RE = re.compile(r"(?P<key>[\w.@/-]+)=(?P<value>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s]+)")


def clamp_confidence(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Ограничивает числовое значение заданными границами. Область применения: уверенности.
    
    Args:
        value (float): Входное значение, которое нужно проверить, преобразовать или нормализовать.
        minimum (float, optional): Нижняя допустимая граница значения.
        maximum (float, optional): Верхняя допустимая граница значения.
    
    Returns:
        float: Значение уверенности, ограниченное переданными нижней и верхней границами.
    """
    return max(minimum, min(maximum, value))


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Разбирает входные данные и преобразует их в структурированный результат. Область применения: временной метки.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Optional[datetime]: Распознанная временная метка; None, если значение пустое или не подходит ни под один поддерживаемый формат.
    """
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace(",", ".", 1) if "," in text and "T" in text else text
    # Перебираем несколько распространенных форматов времени, потому что логи разных систем пишут дату по-разному.
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text[:-1] + "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def normalize_level(value: Any) -> Optional[str]:
    """Нормализует входное значение к каноническому виду, удобному для сравнения и агрегации. Область применения: уровня логирования.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Optional[str]: Канонический уровень логирования (`INFO`, `WARN`, `ERROR` и т.п.) или None для пустого/некорректного значения.
    """
    if value in (None, ""):
        return None
    text = str(value).strip().upper()
    return LEVEL_ALIASES.get(text, text if text.isalpha() else None)


def parse_float(value: Any) -> Optional[float]:
    """Разбирает входные данные и преобразует их в структурированный результат.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Optional[float]: Число с плавающей точкой или None, если значение пустое либо не является числом.
    """
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_int(value: Any) -> Optional[int]:
    """Разбирает входные данные и преобразует их в структурированный результат.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Optional[int]: Целое число или None, если значение пустое либо не является целым числом.
    """
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def strip_quotes(value: str) -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        value (str): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        str: Исходная строка без одинаковых внешних кавычек; если кавычек нет, строка возвращается без изменений.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def read_detection_sample(text: str, max_lines: int = 40) -> str:
    """Читает входные данные и возвращает подготовленное представление для дальнейшей обработки.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
        max_lines (int, optional): Максимальное число строк, которое берется из входного текста.
    
    Returns:
        str: Первые `max_lines` строк текста, объединенные обратно в строку для детектора парсера.
    """
    return "\n".join(text.splitlines()[:max_lines])


def parse_logfmt_pairs(line: str) -> dict[str, str]:
    """Разбирает входные данные и преобразует их в структурированный результат.
    
    Args:
        line (str): Одна строка лога, которую нужно разобрать или проверить.
    
    Returns:
        dict[str, str]: Словарь logfmt-пар `ключ -> значение` с удаленными внешними кавычками.
    """
    result: dict[str, str] = {}
    # Регулярное выражение учитывает кавычки, поэтому значения с пробелами не дробятся на отдельные пары.
    for match in LOGFMT_RE.finditer(line):
        result[match.group("key")] = strip_quotes(match.group("value"))
    return result


def coerce_latency_ms(value: Any) -> Optional[float]:
    """Преобразует значение к ожидаемому типу с учетом допустимых нестрогих форматов. Область применения: задержки.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Optional[float]: Задержка в миллисекундах; секунды переводятся в миллисекунды, неподходящие значения дают None.
    """
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    if not text:
        return None
    if text.endswith("ms"):
        return parse_float(text[:-2].strip())
    if text.endswith("s"):
        parsed = parse_float(text[:-1].strip())
        return None if parsed is None else parsed * 1000.0
    return parse_float(text)


def first_present(mapping: Mapping[str, Any], *keys: str) -> Any:
    """Возвращает первое подходящее значение из набора кандидатов.
    
    Args:
        mapping (Mapping[str, Any]): Словарь или отображение, из которого извлекаются значения по набору ключей.
        *keys (str): Значение `keys`, используемое функцией при выполнении операции.
    
    Returns:
        Any: Значение первого найденного ключа без учета регистра; None, если ни один ключ отсутствует.
    """
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def extract_ids(text: str) -> tuple[Optional[str], Optional[str]]:
    """Извлекает из входных данных значимые признаки или идентификаторы.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
    
    Returns:
        tuple[Optional[str], Optional[str]]: Пара `(request_id, trace_id)`, извлеченная из текста; элементы могут быть None.
    """
    request_match = REQUEST_ID_RE.search(text)
    trace_match = TRACE_ID_RE.search(text)
    request_id = request_match.group("value") if request_match else None
    trace_id = trace_match.group("value") if trace_match else None
    return request_id, trace_id


def extract_http_tokens(text: str) -> dict[str, Any]:
    """Извлекает из входных данных значимые признаки или идентификаторы.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
    
    Returns:
        dict[str, Any]: HTTP-признаки из текста: метод, путь, статус, задержка, размер ответа и IP клиента.
    """
    method = None
    path = None
    status = None
    latency_ms = None
    response_size = None
    client_ip = None

    path_match = HTTP_PATH_RE.search(text)
    if path_match:
        path = path_match.group("value")
    method_match = HTTP_METHOD_RE.search(text)
    if method_match:
        method = method_match.group(1).upper()
    status_match = STATUS_RE.search(text)
    if status_match:
        status = parse_int(status_match.group("value"))
    latency_match = LATENCY_RE.search(text)
    if latency_match:
        value = parse_float(latency_match.group("value"))
        unit = (latency_match.group("unit") or "ms").lower()
        if value is not None:
            latency_ms = value * 1000.0 if unit == "s" else value
    size_match = SIZE_RE.search(text)
    if size_match:
        response_size = parse_int(size_match.group("value"))
    ip_match = IP_RE.search(text)
    if ip_match:
        client_ip = ip_match.group("value")
    return {
        "http_method": method,
        "http_path": path,
        "http_status": status,
        "latency_ms": latency_ms,
        "response_size": response_size,
        "client_ip": client_ip,
    }


def stringify(value: Any) -> str:
    """Преобразует значение произвольного типа в строку для сохранения или анализа.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        str: Строковое представление значения: списки объединяются строками, словари сериализуются в JSON.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(stringify(item) for item in value if item is not None)
    if isinstance(value, Mapping):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def build_event_from_mapping(
    payload: Mapping[str, Any],
    *,
    raw_text: str,
    parser_name: str,
    parser_confidence: float,
    source: str | None,
    line_count: int = 1,
    default_message: str | None = None,
    default_component: str | None = None,
) -> CanonicalEvent:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: события.
    
    Args:
        payload (Mapping[str, Any]): Словарь с исходными или уже подготовленными данными для преобразования.
        raw_text (str): Исходный текст записи лога, сохраняемый для диагностики и повторного анализа.
        parser_name (str): Имя парсера, которым была обработана запись.
        parser_confidence (float): Оценка уверенности парсера в корректности разбора записи.
        source (str | None): Имя источника или файла, из которого получена запись лога.
        line_count (int, optional): Количество строк, входящих в одну логическую запись лога.
        default_message (str | None, optional): Сообщение по умолчанию, используемое если его нельзя извлечь из данных.
        default_component (str | None, optional): Компонент по умолчанию, используемый если он отсутствует во входных данных.
    
    Returns:
        CanonicalEvent: Каноническое событие, собранное из словаря лога, исходного текста и извлеченных HTTP/trace-признаков.
    """
    request_id, trace_id = extract_ids(raw_text)
    http_tokens = extract_http_tokens(raw_text)
    timestamp = parse_timestamp(
        first_present(payload, "@timestamp", "timestamp", "time", "ts", "datetime", "date")
    )
    level = normalize_level(first_present(payload, "level", "severity", "log_level", "lvl"))
    source_value = first_present(payload, "source", "logger", "service", "file") or source
    component = first_present(payload, "component", "module", "context", "logger", "class") or default_component
    message = stringify(first_present(payload, "message", "msg", "body", "log", "event")) or default_message or raw_text
    stacktrace = stringify(first_present(payload, "stacktrace", "stack", "exception_stack"))
    if not stacktrace:
        exception_value = first_present(payload, "exception", "error")
        if isinstance(exception_value, Mapping):
            stacktrace = stringify(exception_value)
        elif exception_value and not isinstance(exception_value, (int, float)):
            stacktrace = stringify(exception_value)
    request_id = stringify(first_present(payload, "request_id", "requestid", "requestId")) or request_id
    trace_id = stringify(first_present(payload, "trace_id", "traceid", "traceId", "correlation_id", "correlationid")) or trace_id
    http_method = stringify(first_present(payload, "http_method", "method", "verb")) or http_tokens["http_method"]
    http_path = stringify(first_present(payload, "http_path", "path", "uri", "endpoint", "url")) or http_tokens["http_path"]
    http_status = parse_int(first_present(payload, "http_status", "status", "status_code")) or http_tokens["http_status"]
    latency_ms = coerce_latency_ms(first_present(payload, "latency_ms", "duration_ms", "elapsed_ms", "latency", "duration")) or http_tokens["latency_ms"]
    response_size = parse_int(first_present(payload, "response_size", "bytes", "size", "response_bytes")) or http_tokens["response_size"]
    client_ip = stringify(first_present(payload, "client_ip", "ip", "remote_ip", "c-ip")) or http_tokens["client_ip"]
    user_agent = stringify(first_present(payload, "user_agent", "user-agent", "ua", "agent"))

    # Все распознанные поля исключаем из attributes, чтобы в дополнительной нагрузке остались только исходные нестандартные данные.
    known_keys = {
        "@timestamp",
        "timestamp",
        "time",
        "ts",
        "datetime",
        "date",
        "level",
        "severity",
        "log_level",
        "lvl",
        "source",
        "logger",
        "service",
        "file",
        "component",
        "module",
        "context",
        "class",
        "message",
        "msg",
        "body",
        "log",
        "event",
        "stacktrace",
        "stack",
        "exception_stack",
        "exception",
        "error",
        "request_id",
        "requestid",
        "requestId",
        "trace_id",
        "traceid",
        "traceId",
        "correlation_id",
        "correlationid",
        "http_method",
        "method",
        "verb",
        "http_path",
        "path",
        "uri",
        "endpoint",
        "url",
        "http_status",
        "status",
        "status_code",
        "latency_ms",
        "duration_ms",
        "elapsed_ms",
        "latency",
        "duration",
        "response_size",
        "bytes",
        "size",
        "response_bytes",
        "client_ip",
        "ip",
        "remote_ip",
        "c-ip",
        "user_agent",
        "user-agent",
        "ua",
        "agent",
    }
    attributes = {str(key): value for key, value in payload.items() if str(key).lower() not in known_keys}

    return CanonicalEvent(
        timestamp=timestamp,
        level=level,
        source=stringify(source_value) or source,
        component=stringify(component) or None,
        message=message.strip() or raw_text,
        raw_text=raw_text,
        stacktrace=stacktrace.strip(),
        request_id=request_id or None,
        trace_id=trace_id or None,
        http_method=http_method or None,
        http_path=http_path or None,
        http_status=http_status,
        latency_ms=latency_ms,
        response_size=response_size,
        client_ip=client_ip or None,
        user_agent=user_agent or None,
        parser_name=parser_name,
        parser_confidence=clamp_confidence(parser_confidence),
        attributes=attributes,
        line_count=line_count,
    )


def build_generic_event(
    raw_text: str,
    *,
    parser_name: str,
    parser_confidence: float,
    source: str | None,
    line_count: int = 1,
    default_component: str | None = None,
) -> CanonicalEvent:
    """Формирует и возвращает структуру данных, объект или сводку для дальнейшей обработки. Область применения: события.
    
    Args:
        raw_text (str): Исходный текст записи лога, сохраняемый для диагностики и повторного анализа.
        parser_name (str): Имя парсера, которым была обработана запись.
        parser_confidence (float): Оценка уверенности парсера в корректности разбора записи.
        source (str | None): Имя источника или файла, из которого получена запись лога.
        line_count (int, optional): Количество строк, входящих в одну логическую запись лога.
        default_component (str | None, optional): Компонент по умолчанию, используемый если он отсутствует во входных данных.
    
    Returns:
        CanonicalEvent: Каноническое событие с минимальной структурой, построенное из произвольного текстового сообщения.
    """
    request_id, trace_id = extract_ids(raw_text)
    http_tokens = extract_http_tokens(raw_text)
    return CanonicalEvent(
        timestamp=None,
        level=None,
        source=source,
        component=default_component,
        message=raw_text.strip(),
        raw_text=raw_text.strip(),
        stacktrace="",
        request_id=request_id,
        trace_id=trace_id,
        http_method=http_tokens["http_method"],
        http_path=http_tokens["http_path"],
        http_status=http_tokens["http_status"],
        latency_ms=http_tokens["latency_ms"],
        response_size=http_tokens["response_size"],
        client_ip=http_tokens["client_ip"],
        parser_name=parser_name,
        parser_confidence=clamp_confidence(parser_confidence),
        attributes={},
        line_count=line_count,
    )


def summarize_parse_result(
    *,
    parser_name: str,
    events: list[CanonicalEvent],
    total_lines: int,
    warnings: Optional[list[str]] = None,
    fallback_events: int = 0,
    confidence_cap: float = 1.0,
) -> ParseResult:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        parser_name (str): Имя парсера, которым была обработана запись.
        events (list[CanonicalEvent]): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        total_lines (int): Список строк лога, обрабатываемых функцией.
        warnings (Optional[list[str]], optional): Значение `warnings`, используемое функцией при выполнении операции.
        fallback_events (int, optional): Список или поток событий, на основе которого строятся агрегаты, отчеты или выводы.
        confidence_cap (float, optional): Значение `confidence_cap`, используемое функцией при выполнении операции.
    
    Returns:
        ParseResult: Итог парсинга с событиями, общей уверенностью, статистикой строк, предупреждениями и fallback-счетчиком.
    """
    warnings = list(warnings or [])
    total_events = len(events)
    consumed_lines = sum(max(event.line_count, 1) for event in events)
    timestamp_count = sum(1 for event in events if event.timestamp is not None)
    level_count = sum(1 for event in events if event.level is not None)
    multiline_events_count = sum(1 for event in events if event.line_count > 1)
    structured_count = sum(
        1
        for event in events
        if any(
            (
                event.component,
                event.request_id,
                event.trace_id,
                event.http_method,
                event.http_path,
                event.http_status is not None,
                event.latency_ms is not None,
                event.attributes,
            )
        )
    )
    timestamp_ratio = timestamp_count / total_events if total_events else 0.0
    level_ratio = level_count / total_events if total_events else 0.0
    structured_ratio = structured_count / total_events if total_events else 0.0
    fallback_ratio = fallback_events / total_events if total_events else 1.0
    line_coverage = consumed_lines / total_lines if total_lines else 0.0
    confidence = clamp_confidence(
        0.35 * line_coverage
        + 0.25 * timestamp_ratio
        + 0.15 * level_ratio
        + 0.15 * structured_ratio
        + 0.10 * (1.0 - fallback_ratio),
        maximum=confidence_cap,
    )
    stats = {
        "total_lines": total_lines,
        "total_events": total_events,
        "parsed_timestamp_ratio": timestamp_ratio,
        "parsed_level_ratio": level_ratio,
        "fallback_ratio": fallback_ratio,
        "multiline_events_count": multiline_events_count,
    }
    return ParseResult(
        events=events,
        parser_name=parser_name,
        confidence=confidence,
        stats=stats,
        warnings=warnings,
    )


def non_empty_lines(text: str) -> list[str]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
    
    Returns:
        list[str]: Непустые строки текста без окружающих пробелов.
    """
    return [line for line in text.splitlines() if line.strip()]


def safe_json_loads(line: str) -> Any:
    """Выполняет вспомогательную операцию для JSON.
    
    Args:
        line (str): Одна строка лога, которую нужно разобрать или проверить.
    
    Returns:
        Any: Разобранное JSON-значение или None, если строка не является корректным JSON.
    """
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

