from __future__ import annotations

from dataclasses import dataclass
import re

from ..base import BaseParser
from ..models import CanonicalEvent
from ..utils import clamp_confidence, normalize_level, parse_timestamp, summarize_parse_result

WINDOWS_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*"
    r"(?P<level>[A-Za-z]+)\s+"
    r"(?P<component>CBS|CSI)\s+"
    r"(?P<body>.*)$"
)
CSI_PREFIX_RE = re.compile(
    r"^(?P<prefix>[0-9A-Fa-f]{8}(?:@\S+)?)\s+(?P<message>.*)$"
)


@dataclass
class ParsedWindowsLine:
    timestamp: object
    level: str | None
    component: str
    message: str
    attributes: dict


def parse_windows_line(line: str) -> ParsedWindowsLine | None:
    """Разбирает входные данные и преобразует их в структурированный результат. Область применения: Windows servicing.
    
    Args:
        line (str): Одна строка лога, которую нужно разобрать или проверить.
    
    Returns:
        ParsedWindowsLine | None: Разобранная строка Windows servicing с датой, временем, уровнем, компонентом и сообщением; None при несовпадении формата.
    """
    match = WINDOWS_LINE_RE.match(line.rstrip())
    if not match:
        return None
    body = (match.group("body") or "").strip()
    attributes: dict = {}
    component = match.group("component")
    if component == "CSI":
        prefix_match = CSI_PREFIX_RE.match(body)
        if prefix_match:
            attributes["csi_prefix"] = prefix_match.group("prefix")
            body = prefix_match.group("message").strip()
    return ParsedWindowsLine(
        timestamp=parse_timestamp(match.group("timestamp")),
        level=normalize_level(match.group("level")),
        component=component,
        message=body or line.strip(),
        attributes=attributes,
    )


def is_windows_start(line: str) -> bool:
    """Проверяет условие и возвращает логический результат. Область применения: Windows servicing.
    
    Args:
        line (str): Одна строка лога, которую нужно разобрать или проверить.
    
    Returns:
        bool: True, если строка выглядит как начало записи Windows servicing.
    """
    return bool(WINDOWS_LINE_RE.match(line.rstrip()))


class WindowsServicingParser(BaseParser):
    """Парсер логов Windows servicing с записями CBS/CSI."""

    name = "windows_servicing"

    def can_parse(self, sample: str) -> float:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            sample (str): Образец текста лога, по которому оценивается применимость парсера.

        Returns:
            float: Оценка уверенности от 0.0 до 1.0, показывающая насколько парсер подходит для текста.
        """
        lines = [line for line in sample.splitlines() if line.strip()]
        if not lines:
            return 0.0
        matches = sum(1 for line in lines if is_windows_start(line))
        return matches / len(lines)

    def parse(self, text: str, source: str | None = None):
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
            source (str | None, optional): Имя источника или файла, из которого получена запись лога.

        Returns:
            ParseResult: Результат парсинга с событиями, диагностикой и предупреждениями.
        """
        events: list[CanonicalEvent] = []
        warnings: list[str] = []
        lines = text.splitlines()
        buffer: list[str] = []

        def flush_buffer() -> None:
            """Выполняет вспомогательную операцию для логики проекта.

            Args:
                Нет параметров.

            Returns:
                None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
            """
            if not buffer:
                return
            first_line = buffer[0]
            parsed = parse_windows_line(first_line)
            raw_text = "\n".join(buffer).strip()
            if parsed is None:
                warnings.append("Unexpected non-Windows block in windows_servicing parser")
                buffer.clear()
                return
            continuation = "\n".join(line.rstrip() for line in buffer[1:]).strip()
            stacktrace = continuation if continuation else ""
            events.append(
                CanonicalEvent(
                    timestamp=parsed.timestamp,
                    level=parsed.level,
                    source=source,
                    component=parsed.component,
                    message=parsed.message,
                    raw_text=raw_text,
                    stacktrace=stacktrace,
                    parser_name=self.name,
                    parser_confidence=clamp_confidence(0.96 if parsed.level else 0.86),
                    attributes=parsed.attributes,
                    line_count=len(buffer),
                )
            )
            buffer.clear()

        for line in lines:
            if not line.strip():
                continue
            if is_windows_start(line):
                flush_buffer()
                buffer.append(line)
            elif buffer:
                buffer.append(line)
            else:
                warnings.append("Encountered orphan continuation in windows_servicing parser")
                buffer = [line]
        flush_buffer()

        return summarize_parse_result(
            parser_name=self.name,
            events=events,
            total_lines=len(lines),
            warnings=warnings,
            fallback_events=0,
        )
