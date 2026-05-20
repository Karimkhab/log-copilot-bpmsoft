from __future__ import annotations

from abc import ABC, abstractmethod

from .models import ParseResult


class BaseParser(ABC):
    """Базовый контракт для реализаций парсеров."""

    name: str

    @abstractmethod
    def can_parse(self, sample: str) -> float:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            sample (str): Образец текста лога, по которому оценивается применимость парсера.

        Returns:
            float: Оценка уверенности от 0.0 до 1.0, показывающая насколько парсер подходит для текста.
        """

    @abstractmethod
    def parse(self, text: str, source: str | None = None) -> ParseResult:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
            source (str | None, optional): Имя источника или файла, из которого получена запись лога.

        Returns:
            ParseResult: Результат парсинга с событиями, диагностикой и предупреждениями.
        """

