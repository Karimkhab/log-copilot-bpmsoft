from __future__ import annotations

"""Final product output assembly for pipeline runs."""

import json
from collections import Counter
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
    """Convert dict/dataclass values to plain dictionaries."""
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    return dict(value) if isinstance(value, dict) else {}


def _scalars(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only JSON scalar fields from a metrics payload."""
    return {
        key: value
        for key, value in payload.items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }


def _write_json(path: Path, payload: Any) -> None:
    """Write one JSON output artifact."""
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write newline-delimited JSON rows for downstream integrations."""
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _card_type(card_payload: Dict[str, Any], profile: str) -> str:
    """Normalize a profile-specific card type for product output."""
    if profile == "incidents" and card_payload.get("cluster_id") == "incidents-observation":
        return "observation"
    return str(card_payload.get("card_type") or profile)


def _source_refs(card_payload: Dict[str, Any], card_type: str) -> List[Dict[str, Any]]:
    """Build compact source references from deterministic card facts."""
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
    """Convert an internal agent card into the public FindingCard contract."""
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
    """Build top-level product metrics from profile and agent outputs."""
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
    """Build the public product summary for a completed run."""
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


def _siem_export_rows(summary: RunSummary, findings: List[FindingCard]) -> List[Dict[str, Any]]:
    """Build a simple SIEM-oriented JSONL export from the final findings."""
    rows = []
    for index, finding in enumerate(findings, start=1):
        rows.append(
            {
                "run_id": summary.run_id,
                "profile": summary.profile,
                "quality_status": summary.quality_status,
                "finding_id": f"{summary.run_id}:{index}",
                "status": summary.status,
                "card_type": finding.card_type,
                "severity": finding.severity,
                "confidence": round(float(finding.confidence), 3),
                "title": finding.title,
                "summary": finding.summary,
                "recommended_actions": list(finding.recommended_actions),
                "limitations": list(finding.limitations),
                "source_refs": list(finding.source_refs),
                "payload": dict(finding.payload),
            }
        )
    return rows


def _zabbix_metrics_payload(summary: RunSummary, findings: List[FindingCard]) -> Dict[str, Any]:
    """Build a compact metrics payload for Zabbix-like ingestion."""
    parser_diagnostics = _dict(summary.parser_diagnostics)
    quality = _dict(summary.quality)
    profile_fit = _dict(summary.profile_fit)
    severity_counts = Counter(finding.severity for finding in findings)
    agent_signals = _dict(_dict(quality.get("signals")).get("agent"))
    metrics = [
        {"key": "logcopilot.event_count", "value": summary.event_count},
        {"key": "logcopilot.finding_count", "value": len(findings)},
        {"key": "logcopilot.quality.score", "value": quality.get("score", 0.0)},
        {"key": "logcopilot.parse_quality.score", "value": _dict(parser_diagnostics.get("parse_quality")).get("score", 0.0)},
        {"key": "logcopilot.parser_confidence.mean", "value": parser_diagnostics.get("mean_parser_confidence", 0.0)},
        {"key": "logcopilot.fallback_ratio", "value": parser_diagnostics.get("fallback_ratio", 0.0)},
        {"key": "logcopilot.profile_fit.selected_score", "value": profile_fit.get("selected_score", 0.0)},
        {"key": "logcopilot.agent.used_llm", "value": 1 if agent_signals.get("used_llm") else 0},
        {"key": "logcopilot.agent.used_fallback", "value": 1 if agent_signals.get("used_fallback") else 0},
        {"key": "logcopilot.findings.critical", "value": severity_counts.get("critical", 0)},
        {"key": "logcopilot.findings.high", "value": severity_counts.get("high", 0)},
        {"key": "logcopilot.findings.medium", "value": severity_counts.get("medium", 0)},
        {"key": "logcopilot.findings.low", "value": severity_counts.get("low", 0)},
    ]
    return {
        "run_id": summary.run_id,
        "profile": summary.profile,
        "status": summary.status,
        "quality_status": summary.quality_status,
        "metrics": metrics,
    }


def run_final_output_generation(context: PipelineContext) -> PipelineContext:
    """Build and persist the final product output for one run."""
    if context.agent_result is None:
        raise RuntimeError("Agent interpretation must run before final output generation.")
    if context.execution_quality is None:
        raise RuntimeError("Execution quality must run before final output generation.")

    previous_summary = _dict(context.run_summary)
    findings = [_to_finding_card(card, context.config.profile) for card in context.agent_result.cards]
    final_summary = _build_run_summary(context, findings)
    findings_path = context.run_dir / "findings.json"
    siem_path = context.run_dir / "siem_findings.jsonl"
    zabbix_path = context.run_dir / "zabbix_metrics.json"

    context.findings = findings
    context.final_summary = final_summary
    context.artifact_paths["run_summary_json"] = str(context.run_dir / "run_summary.json")
    context.artifact_paths["findings_json"] = str(findings_path)
    context.artifact_paths["siem_findings_jsonl"] = str(siem_path)
    context.artifact_paths["zabbix_metrics_json"] = str(zabbix_path)

    final_payload = final_summary.as_dict()
    if "trace_summary" in previous_summary:
        final_payload["trace_summary"] = previous_summary["trace_summary"]

    context.run_summary = final_payload

    _write_json(findings_path, [finding.as_dict() for finding in findings])
    _write_jsonl(siem_path, _siem_export_rows(final_summary, findings))
    _write_json(zabbix_path, _zabbix_metrics_payload(final_summary, findings))
    write_run_summary_json(context.run_dir / "run_summary.json", final_payload)
    return context


__all__ = ["run_final_output_generation"]
