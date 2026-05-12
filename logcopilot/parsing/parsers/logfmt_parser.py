from __future__ import annotations

from ..base import BaseParser
from ..utils import build_event_from_mapping, build_generic_event, non_empty_lines, parse_logfmt_pairs, summarize_parse_result


class LogfmtParser(BaseParser):
    """Парсер строк logfmt или общих строк вида ключ=значение."""

    name = "logfmt"

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
        scores = []
        for line in lines:
            coverage = sum(len(match.group(0)) for match in parse_logfmt_pairs_with_spans(line))
            pairs = parse_logfmt_pairs(line)
            if len(pairs) < 2:
                scores.append(0.0)
                continue
            scores.append(coverage / max(len(line), 1))
        return sum(scores) / len(scores)

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
            pairs = parse_logfmt_pairs(line)
            if pairs:
                events.append(
                    build_event_from_mapping(
                        pairs,
                        raw_text=line,
                        parser_name=self.name,
                        parser_confidence=0.85,
                        source=source,
                    )
                )
                continue
            fallback_events += 1
            warnings.append(f"Line {index} has no parseable key=value pairs")
            events.append(build_generic_event(line, parser_name="generic_fallback", parser_confidence=0.25, source=source))
        return summarize_parse_result(
            parser_name=self.name,
            events=events,
            total_lines=len(lines),
            warnings=warnings,
            fallback_events=fallback_events,
        )


def parse_logfmt_pairs_with_spans(line: str):
    """Разбирает входные данные и преобразует их в структурированный результат.
    
    Args:
        line (str): Одна строка лога, которую нужно разобрать или проверить.
    
    Returns:
        Any: Пары `key=value` вместе с позициями совпадений, чтобы восстановить сообщение вне logfmt-полей.
    """
    from ..utils import LOGFMT_RE

    return list(LOGFMT_RE.finditer(line))
