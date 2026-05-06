from __future__ import annotations

from dataclasses import dataclass

from .base import BaseParser
from .models import ParserSelection


@dataclass
class RegisteredParser:
    parser: BaseParser
    is_fallback: bool = False


class ParserRegistry:
    """Реестр реализаций парсеров и правил выбора."""

    def __init__(self, fallback_threshold: float = 0.45) -> None:
        """Инициализирует объект и сохраняет параметры, необходимые для дальнейшей работы.

        Args:
            fallback_threshold (float, optional): Значение `fallback_threshold`, используемое функцией при выполнении операции.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        self.fallback_threshold = fallback_threshold
        self._parsers: list[RegisteredParser] = []

    def register(self, parser: BaseParser, *, is_fallback: bool = False) -> None:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            parser (BaseParser): Объект парсера или построитель аргументов, который настраивается функцией.
            is_fallback (bool, optional): Резервные детерминированные данные, используемые при неполном ответе модели.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        self._parsers.append(RegisteredParser(parser=parser, is_fallback=is_fallback))

    def get_fallback(self) -> BaseParser:
        """Возвращает данные из хранилища или подготовленной структуры по заданным условиям. Область применения: резервного сценария.
        
        Args:
            Нет параметров.
        
        Returns:
            BaseParser: Парсер, зарегистрированный как fallback для нераспознанных или слабоструктурированных логов.
        
        Raises:
            LookupError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
        """
        for entry in self._parsers:
            if entry.is_fallback:
                return entry.parser
        raise LookupError("ParserRegistry requires a fallback parser")

    def select(self, sample: str) -> tuple[BaseParser, ParserSelection]:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            sample (str): Образец текста лога, по которому оценивается применимость парсера.
        
        Returns:
            tuple[BaseParser, ParserSelection]: Выбранный парсер и диагностика выбора с уверенностью и признаком fallback.
        """
        fallback = self.get_fallback()
        scored: list[tuple[float, RegisteredParser]] = []
        for entry in self._parsers:
            if entry.is_fallback:
                continue
            confidence = entry.parser.can_parse(sample)
            scored.append((confidence, entry))
        if not scored:
            return fallback, ParserSelection(parser_name=fallback.name, confidence=0.0, used_fallback=True)
        best_score, best_entry = max(scored, key=lambda item: item[0])
        if best_score < self.fallback_threshold:
            return fallback, ParserSelection(parser_name=fallback.name, confidence=best_score, used_fallback=True)
        return best_entry.parser, ParserSelection(parser_name=best_entry.parser.name, confidence=best_score, used_fallback=False)

