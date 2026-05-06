from __future__ import annotations

"""Сборка итогового продуктового вывода для запусков конвейера."""

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List

from ..domain import FindingCard, PipelineContext, RunSummary
from .reporting import write_run_summary_json

_COMMON_CARD_FIELDS = {
    "card_type",
    "title",
    "severity",
    "confidence",
    "summary",
    "evidence",
    "recommended_actions",
    "limitations",
}


def _dict(value: Any) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        value (Any): Входное значение, которое нужно проверить, преобразовать или нормализовать.
    
    Returns:
        Dict[str, Any]: Копия входного словаря или пустой словарь, если значение не является mapping.
    """
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    return dict(value) if isinstance(value, dict) else {}


def _scalars(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        payload (Dict[str, Any]): Словарь с исходными или уже подготовленными данными для преобразования.
    
    Returns:
        Dict[str, Any]: Только скалярные JSON-совместимые поля payload, без вложенных списков и словарей.
    """
    return {
        key: value
        for key, value in payload.items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }


def _write_json(path: Path, payload: Any) -> None:
    """Записывает внутренний файл или артефакт, используемый отчетностью конвейера. Область применения: JSON.

    Args:
        path (Path): Путь к файлу или артефакту, с которым работает функция.
        payload (Any): Словарь с исходными или уже подготовленными данными для преобразования.

    Returns:
        None: Функция изменяет состояние, выполняет проверку или запись и не возвращает полезное значение.
    """
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _card_type(card_payload: Dict[str, Any], profile: str) -> str:
    """Выполняет вспомогательную операцию для карточки.
    
    Args:
        card_payload (Dict[str, Any]): Словарь с полями карточки, полученный от модели или детерминированного слоя.
        profile (str): Профиль анализа логов, определяющий набор вычислений и формат результата.
    
    Returns:
        str: Тип итоговой карточки: observation для наблюдательного incident-кейса, иначе card_type из payload или текущий профиль.
    """
    if profile == "incidents" and card_payload.get("cluster_id") == "incidents-observation":
        return "observation"
    return str(card_payload.get("card_type") or profile)


def _source_refs(card_payload: Dict[str, Any], card_type: str) -> List[Dict[str, Any]]:
    """Выполняет вспомогательную операцию для логики проекта.
    
    Args:
        card_payload (Dict[str, Any]): Словарь с полями карточки, полученный от модели или детерминированного слоя.
        card_type (str): Тип карточки, определяющий способ извлечения ссылок на источники.
    
    Returns:
        List[Dict[str, Any]]: Список словарей с нормализованными фактами или строками отчета.
    """
    if card_type in {"incident", "observation"}:
        return [
            {
                "type": "cluster",
                "cluster_id": card_payload.get("cluster_id", ""),
                "first_seen": card_payload.get("first_seen", ""),
                "last_seen": card_payload.get("last_seen", ""),
            }
        ]
    if card_type == "heatmap":
        return [
            {
                "type": "heatmap_bucket",
                "bucket_start": card_payload.get("bucket_start", ""),
                "component": card_payload.get("component", ""),
                "operation": card_payload.get("operation", ""),
            }
        ]
    if card_type == "traffic":
        return [
            {
                "type": "traffic_pattern",
                "method": card_payload.get("method", ""),
                "path": card_payload.get("path", ""),
                "http_status": card_payload.get("http_status"),
            }
        ]
    return []


def _to_finding_card(card: Any, profile: str) -> FindingCard:
    """Выполняет вспомогательную операцию для карточки.
    
    Args:
        card (Any): Карточка вывода или ее полезная нагрузка, которую нужно преобразовать.
        profile (str): Профиль анализа логов, определяющий набор вычислений и формат результата.
    
    Returns:
        FindingCard: Финальная продуктовая карточка с типом, заголовком, серьезностью, summary, evidence, действиями и source_refs.
    """
    card_payload = card.as_dict() if hasattr(card, "as_dict") else _dict(card)
    card_type = _card_type(card_payload, profile)
    payload = {
        key: value
        for key, value in card_payload.items()
        if key not in _COMMON_CARD_FIELDS
    }
    return FindingCard(
        card_type=card_type,
        title=str(card_payload.get("title") or ""),
        severity=str(card_payload.get("severity") or "medium"),
        confidence=float(card_payload.get("confidence") or 0.0),
        summary=str(card_payload.get("summary") or ""),
        evidence=list(card_payload.get("evidence") or []),
        recommended_actions=list(card_payload.get("recommended_actions") or []),
        limitations=list(card_payload.get("limitations") or []),
        source_refs=_source_refs(card_payload, card_type),
        payload=payload,
    )


def _build_key_metrics(context: PipelineContext) -> Dict[str, Any]:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        Dict[str, Any]: Основные метрики запуска для публичной сводки: профиль, события, качество, parser-fit и профильные счетчики.
    """
    profile_summary = _dict(context.profile_result.summary if context.profile_result else {})
    metrics = _scalars(profile_summary)
    agent_result = context.agent_result
    if agent_result is not None:
        metrics.update(
            {
                "finding_count": len(agent_result.cards),
                "agent_confidence": round(float(agent_result.confidence), 3),
                "agent_overall_status": agent_result.overall_status,
                "agent_mode": agent_result.mode,
                "agent_provider": agent_result.provider,
            }
        )
    return metrics


def _build_run_summary(context: PipelineContext, findings: List[FindingCard]) -> RunSummary:
    """Формирует внутреннюю структуру данных, объект или сводку для дальнейшей обработки. Область применения: сводки.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
        findings (List[FindingCard]): Значение `findings`, используемое функцией при выполнении операции.
    
    Returns:
        RunSummary: Итоговая продуктовая сводка запуска с метриками, качеством, находками и путями артефактов.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if context.execution_quality is None:
        raise RuntimeError("Execution quality must be validated before final output.")
    if context.agent_result is None:
        raise RuntimeError("Agent interpretation must run before final output.")
    run_summary = _dict(context.run_summary)
    agent_result = context.agent_result
    return RunSummary(
        run_id=context.run_id,
        profile=context.config.profile,
        status="completed",
        event_count=int(run_summary.get("event_count", len(context.events))),
        quality_status=context.execution_quality.status,
        short_summary=agent_result.short_summary,
        technical_summary=agent_result.technical_summary,
        business_summary=agent_result.business_summary,
        parser_diagnostics=_dict(run_summary.get("parser_diagnostics")),
        profile_fit=_dict(run_summary.get("profile_fit")),
        key_metrics=_build_key_metrics(context),
        key_findings=list(agent_result.key_findings),
        recommended_actions=list(agent_result.recommended_actions),
        limitations=list(agent_result.limitations),
        quality=context.execution_quality.as_dict(),
    )


def run_final_output_generation(context: PipelineContext) -> PipelineContext:
    """Выполняет этап конвейера или профиль анализа и возвращает обновленный результат работы.
    
    Args:
        context (PipelineContext): Контекст выполнения конвейера с конфигурацией, промежуточными результатами и путями артефактов.
    
    Returns:
        PipelineContext: Обновленный контекст конвейера после выполнения этапа `run_final_output_generation`.
    
    Raises:
        RuntimeError: Возникает, если входные данные или состояние не позволяют выполнить операцию корректно.
    """
    if context.agent_result is None:
        raise RuntimeError("Agent interpretation must run before final output generation.")
    if context.execution_quality is None:
        raise RuntimeError("Execution quality must run before final output generation.")

    previous_summary = _dict(context.run_summary)
    findings = [_to_finding_card(card, context.config.profile) for card in context.agent_result.cards]
    final_summary = _build_run_summary(context, findings)

    context.findings = findings
    context.final_summary = final_summary
    context.artifact_paths["findings_json"] = str(context.run_dir / "findings.json")

    final_payload = final_summary.as_dict()
    if "trace_summary" in previous_summary:
        final_payload["trace_summary"] = previous_summary["trace_summary"]

    context.run_summary = final_payload

    _write_json(context.run_dir / "findings.json", [finding.as_dict() for finding in findings])
    write_run_summary_json(context.run_dir / "run_summary.json", final_payload)
    return context


__all__ = ["run_final_output_generation"]
