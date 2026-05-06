from __future__ import annotations

"""Небольшая конфигурация провайдера для однократного агентского этапа конвейера."""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Dict


YANDEX_BASE_URL = "https://llm.api.cloud.yandex.net/v1"
DEFAULT_YANDEX_MODEL = "yandexgpt"
DEFAULT_YANDEX_TIMEOUT_SECONDS = 15.0

MAX_AGENT_TEXT_CHARS = 600
MAX_AGENT_LIST_ITEMS = 8
MAX_INCIDENT_CARDS = 5
MAX_HEATMAP_CARDS = 6
MAX_TRAFFIC_CARDS = 6
MAX_SAMPLE_MESSAGES = 3

AGENT_CONTEXT_LIMITS = {
    "max_text_chars": MAX_AGENT_TEXT_CHARS,
    "max_list_items": MAX_AGENT_LIST_ITEMS,
    "max_incident_cards": MAX_INCIDENT_CARDS,
    "max_heatmap_cards": MAX_HEATMAP_CARDS,
    "max_traffic_cards": MAX_TRAFFIC_CARDS,
    "max_sample_messages": MAX_SAMPLE_MESSAGES,
}


@dataclass(frozen=True)
class AgentModelConfig:
    """Конфигурация времени выполнения для одного опционального структурированного вызова языковой модели."""

    provider: str = "none"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    folder_id: str = ""
    timeout_seconds: float = DEFAULT_YANDEX_TIMEOUT_SECONDS


def _dotenv_path() -> Path | None:
    """Выполняет вспомогательную операцию для пути.
    
    Args:
        Нет параметров.
    
    Returns:
        Path | None: Путь к ближайшему `.env` в текущей директории или родителях; None, если файл не найден.
    """
    cwd = Path.cwd().resolve()
    for directory in (cwd, *cwd.parents):
        candidate = directory / ".env"
        if candidate.exists():
            return candidate
    return None


def _read_dotenv() -> Dict[str, str]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        Нет параметров.
    
    Returns:
        Dict[str, str]: Пары ключ-значение из `.env`; пустой словарь, если файл отсутствует или не содержит подходящих строк.
    """
    path = _dotenv_path()
    if path is None:
        return {}

    values: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            values[key] = value
    return values


def _env(name: str, dotenv_values: Dict[str, str], default: str = "") -> str:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
        dotenv_values (Dict[str, str]): Значения, прочитанные из dotenv-файла и используемые вместе с окружением.
        default (str, optional): Значение по умолчанию, возвращаемое при невозможности корректного преобразования.
    
    Returns:
        str: Значение переменной из окружения или `.env`, очищенное от пробелов; если переменной нет, возвращается default.
    """
    if name in os.environ:
        return os.environ[name].strip()
    return dotenv_values.get(name, default).strip()


def _float_env(name: str, dotenv_values: Dict[str, str], default: float) -> float:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        name (str): Имя переменной, поля, провайдера или ресурса, значение которого обрабатывается.
        dotenv_values (Dict[str, str]): Значения, прочитанные из dotenv-файла и используемые вместе с окружением.
        default (float): Значение по умолчанию, возвращаемое при невозможности корректного преобразования.
    
    Returns:
        float: Числовое значение переменной окружения или default, если значение отсутствует либо не разбирается как число.
    """
    raw_value = _env(name, dotenv_values, str(default))
    try:
        return float(raw_value)
    except ValueError:
        return default


def resolve_agent_model_config(provider: str) -> AgentModelConfig:
    """Выполняет вспомогательную операцию для агентского этапа, конфигурации.
    
    Args:
        provider (str): Имя провайдера внешней модели, для которого строится конфигурация.
    
    Returns:
        AgentModelConfig: Полная конфигурация выбранного провайдера агента с моделью, URL, ключом, folder_id и таймаутом.
    
    Raises:
        ValueError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    provider = (provider or "none").lower()
    if provider == "none":
        return AgentModelConfig(provider="none")
    if provider != "yandex":
        raise ValueError(f"Unsupported agent provider: {provider}")

    dotenv_values = _read_dotenv()
    folder_id = _env("YC_FOLDER_ID", dotenv_values)
    model_name = _env("YC_MODEL", dotenv_values, DEFAULT_YANDEX_MODEL) or DEFAULT_YANDEX_MODEL
    model_uri = f"gpt://{folder_id}/{model_name}/latest" if folder_id else ""
    return AgentModelConfig(
        provider="yandex",
        model=model_uri,
        base_url=YANDEX_BASE_URL,
        api_key=_env("YC_AI_API_KEY", dotenv_values),
        folder_id=folder_id,
        timeout_seconds=_float_env("YC_TIMEOUT", dotenv_values, DEFAULT_YANDEX_TIMEOUT_SECONDS),
    )


def provider_is_configured(config: AgentModelConfig) -> bool:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        config (AgentModelConfig): Конфигурация запуска или внешнего провайдера, влияющая на поведение функции.
    
    Returns:
        bool: True, если внешний провайдер содержит все обязательные параметры для вызова модели; иначе False.
    """
    if config.provider == "none":
        return False
    return bool(config.api_key and config.folder_id and config.model and config.base_url)


__all__ = [
    "AGENT_CONTEXT_LIMITS",
    "AgentModelConfig",
    "MAX_AGENT_LIST_ITEMS",
    "MAX_AGENT_TEXT_CHARS",
    "MAX_HEATMAP_CARDS",
    "MAX_INCIDENT_CARDS",
    "MAX_SAMPLE_MESSAGES",
    "MAX_TRAFFIC_CARDS",
    "provider_is_configured",
    "resolve_agent_model_config",
]
