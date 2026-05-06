from __future__ import annotations

from collections.abc import Mapping

from ..base import BaseParser
from ..utils import build_event_from_mapping, build_generic_event, non_empty_lines, safe_json_loads, summarize_parse_result


class JsonParser(BaseParser):
    """Парсер логов с одним JSON-объектом на строку."""

    name = "json"

    def can_parse(self, sample: str) -> float:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            sample (str): Образец текста лога, по которому оценивается применимость парсера.

        Returns:
            float: Оценка уверенности от 0.0 до 1.0, показывающая насколько парсер подходит для текста.
        """
        lines = non_empty_lines(sample)
        if not lines:
            return 0.0
        successes = 0
        for line in lines:
            payload = safe_json_loads(line)
            if isinstance(payload, Mapping):
                successes += 1
        return successes / len(lines)

    def parse(self, text: str, source: str | None = None):
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
            source (str | None, optional): Имя источника или файла, из которого получена запись лога.

        Returns:
            ParseResult: Результат парсинга с событиями, диагностикой и предупреждениями.
        """
        events = []
        warnings: list[str] = []
        fallback_events = 0
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            payload = safe_json_loads(line)
            if isinstance(payload, Mapping):
                events.append(
                    build_event_from_mapping(
                        payload,
                        raw_text=line,
                        parser_name=self.name,
                        parser_confidence=0.95,
                        source=source,
                    )
                )
                continue
            fallback_events += 1
            warnings.append(f"Line {index} is not valid JSON object")
            events.append(build_generic_event(line, parser_name="generic_fallback", parser_confidence=0.25, source=source))
        return summarize_parse_result(
            parser_name=self.name,
            events=events,
            total_lines=len(lines),
            warnings=warnings,
            fallback_events=fallback_events,
        )

