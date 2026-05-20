from __future__ import annotations

"""Нормализация текста: маскирование персональных данных, идентификаторов и временных меток регулярными выражениями."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re
from typing import Dict, Iterable, List, Optional, Tuple

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}(?![\w:])")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
LONG_HEX_RE = re.compile(r"\b[a-f0-9]{16,}\b", re.IGNORECASE)
LONG_ID_RE = re.compile(r"\b\d{4,}\b")
DATETIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?\b"
)
DATE_ONLY_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
TIME_ONLY_RE = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[,.]\d+)?\b")
REQUEST_ID_RE = re.compile(r"(\brequestid\b\s*[:=]?\s*)(\S+)", re.IGNORECASE)
TRACE_ID_RE = re.compile(
    r"(\b(?:traceid|correlationid|activityid|connectionid)\b\s*[:=]?\s*)(\S+)",
    re.IGNORECASE,
)
TOKENISH_RE = re.compile(r"\b[A-Za-z0-9_-]{24,}\b")
WHITESPACE_RE = re.compile(r"\s+")

MASK_SPECS: List[Tuple[str, re.Pattern[str], str]] = [
    ("UUID", UUID_RE, "<UUID>"),
    ("DATETIME", DATETIME_RE, "<DATETIME>"),
    ("DATE", DATE_ONLY_RE, "<DATE>"),
    ("TIME", TIME_ONLY_RE, "<TIME>"),
    ("IP", IPV4_RE, "<IP>"),
    ("IP", IPV6_RE, "<IP>"),
    ("EMAIL", EMAIL_RE, "<EMAIL>"),
    ("JWT", JWT_RE, "<JWT>"),
    ("HEX", HEX_RE, "<HEX>"),
    ("HEX", LONG_HEX_RE, "<HEX>"),
    ("REQ_ID", REQUEST_ID_RE, r"\1<REQ_ID>"),
    ("TRACE_ID", TRACE_ID_RE, r"\1<TRACE_ID>"),
    ("NUM", LONG_ID_RE, "<NUM>"),
    ("TOKEN", TOKENISH_RE, "<TOKEN>"),
]
MASK_TOKEN_NAMES = ("UUID", "IP", "EMAIL", "JWT", "HEX", "REQ_ID", "TRACE_ID", "NUM", "TOKEN")


@dataclass
class NormalizationStats:
    """Накопитель счетчиков и примеров примененных масок нормализации."""

    mask_counts: Counter[str] = field(default_factory=Counter)
    raw_patterns: Dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    total_events: int = 0

    def observe_mask(self, mask_name: str, raw_value: str) -> None:
        """Выполняет вспомогательную операцию для логики проекта.

        Args:
            mask_name (str): Название маски, примененной к динамическому фрагменту текста.
            raw_value (str): Исходное значение до маскирования или нормализации.

        Returns:
            None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
        """
        self.mask_counts[mask_name] += 1
        preview = WHITESPACE_RE.sub(" ", raw_value.strip())[:120]
        if preview:
            self.raw_patterns[mask_name][preview] += 1

    def snapshot(self, top_n: int = 10) -> dict:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            top_n (int, optional): Количество наиболее значимых элементов, которые нужно включить в результат.
        
        Returns:
            dict: Снимок статистики нормализации: счетчики масок и примеры исходных значений.
        """
        return {
            "mask_counts": dict(self.mask_counts),
            "top_replaced_patterns": {
                name: patterns.most_common(top_n)
                for name, patterns in self.raw_patterns.items()
            },
        }


def _apply_mask(
    text: str,
    mask_name: str,
    pattern: re.Pattern[str],
    replacement: str,
    stats: Optional[NormalizationStats],
) -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
        mask_name (str): Название маски, примененной к динамическому фрагменту текста.
        pattern (re.Pattern[str]): Значение `pattern`, используемое функцией при выполнении операции.
        replacement (str): Значение `replacement`, используемое функцией при выполнении операции.
        stats (Optional[NormalizationStats]): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        str: Текст после применения одной регулярной маски и обновления статистики найденных значений.
    """
    if stats is None:
        return pattern.sub(replacement, text)

    def replacer(match: re.Match[str]) -> str:
        """Выполняет вспомогательную операцию для логики проекта.
        
        Args:
            match (re.Match[str]): Значение `match`, используемое функцией при выполнении операции.
        
        Returns:
            str: Токен маски, которым заменяется очередное совпадение регулярного выражения.
        """
        stats.observe_mask(mask_name, match.group(0))
        return match.expand(replacement)

    return pattern.sub(replacer, text)


def normalize_text(text: str, stats: Optional[NormalizationStats] = None) -> str:
    """Нормализует входное значение к каноническому виду, удобному для сравнения и агрегации.
    
    Args:
        text (str): Текстовое содержимое лога или фрагмент строки, которое анализируется функцией.
        stats (Optional[NormalizationStats], optional): Объект статистики нормализации, куда записываются сведения о масках.
    
    Returns:
        str: Нормализованный текст с замаскированными динамическими значениями, сжатыми пробелами и обрезанными краями.
    """
    normalized = text or ""
    if stats is not None:
        stats.total_events += 1
    for mask_name, pattern, replacement in MASK_SPECS:
        normalized = _apply_mask(normalized, mask_name, pattern, replacement, stats)
    normalized = WHITESPACE_RE.sub(" ", normalized).strip().lower()
    return normalized


def count_mask_tokens(texts: Iterable[str]) -> Counter[str]:
    """Подсчитывает элементы или признаки во входной коллекции.
    
    Args:
        texts (Iterable[str]): Набор текстов, в которых нужно подсчитать маски или извлечь признаки.
    
    Returns:
        Counter[str]: Счетчик специальных токенов-масок, найденных во всех переданных текстах.
    """
    counts: Counter[str] = Counter()
    for text in texts:
        upper = (text or "").upper()
        for token_name in MASK_TOKEN_NAMES:
            token = f"<{token_name}>"
            counts[token_name] += upper.count(token)
    return counts
