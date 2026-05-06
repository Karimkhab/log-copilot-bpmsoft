from __future__ import annotations

from .models import ParserSelection
from .registry import ParserRegistry
from .utils import read_detection_sample


def detect_parser(text: str, registry: ParserRegistry) -> ParserSelection:
    """Выполняет вспомогательную операцию для парсера.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
        registry (ParserRegistry): Реестр доступных парсеров, используемый для выбора подходящего обработчика.
    
    Returns:
        ParserSelection: Диагностика выбранного парсера: имя, уверенность детектора и признак fallback-выбора.
    """

    sample = read_detection_sample(text)
    _, selection = registry.select(sample)
    return selection

