from __future__ import annotations

import re

from ..base import BaseParser
from ..models import CanonicalEvent, ParseResult
from ..utils import clamp_confidence, parse_int, parse_timestamp, summarize_parse_result
from .text_multiline_parser import TextMultilineParser

_HTTP_METHODS = "GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD"
_IP_TOKEN_RE = r"(?:::ffff:)?(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:.]+"
_REQUEST_RE = re.compile(
    rf"^(?P<timestamp>\d{{4}}-\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}(?:[,.]\d+)?)\s+"
    rf"(?P<server_ip>{_IP_TOKEN_RE})\s+"
    rf"(?P<method>{_HTTP_METHODS})\s+"
    rf"(?P<path>\S+)\s+-\s+"
    rf"(?P<component>.*?)\s+"
    rf"(?P<client_ip>{_IP_TOKEN_RE})\s+"
    rf"(?P<status>\d{{3}})\s+"
    rf"(?P<size>\d+|-)"
    rf"(?:\s+(?P<tail>.*))?$",
    re.IGNORECASE,
)


class BPMSoftRequestParser(BaseParser):
    """Parser for BPMSoft Request.log HTTP access records."""

    name = "bpmsoft_request"

    def can_parse(self, sample: str) -> float:
        lines = [line for line in sample.splitlines() if line.strip()]
        if not lines:
            return 0.0
        matched = sum(1 for line in lines if _REQUEST_RE.match(line.strip()))
        if matched == 0:
            return 0.0
        return min(1.0, 0.55 + 0.45 * (matched / len(lines)))

    def parse(self, text: str, source: str | None = None) -> ParseResult:
        events: list[CanonicalEvent] = []
        warnings: list[str] = []
        fallback_events = 0
        lines = text.splitlines()

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            match = _REQUEST_RE.match(stripped)
            if match is None:
                fallback_events += 1
                warnings.append(f"Line {index} does not match BPMSoft request pattern")
                continue

            size = parse_int(match.group("size"))
            method = match.group("method").upper()
            path = match.group("path")
            component = (match.group("component") or "").strip() or "request"
            events.append(
                CanonicalEvent(
                    timestamp=parse_timestamp(match.group("timestamp")),
                    level="INFO",
                    source=source,
                    component=component,
                    message=f"{method} {path}",
                    raw_text=line,
                    http_method=method,
                    http_path=path,
                    http_status=parse_int(match.group("status")),
                    response_size=size,
                    client_ip=match.group("client_ip"),
                    parser_name=self.name,
                    parser_confidence=0.92,
                    attributes={
                        "server_ip": match.group("server_ip"),
                        **({"tail": match.group("tail")} if match.group("tail") else {}),
                    },
                    line_count=1,
                )
            )

        return summarize_parse_result(
            parser_name=self.name,
            events=events,
            total_lines=len(lines),
            warnings=warnings,
            fallback_events=fallback_events,
        )


class _BPMSoftTextParser(BaseParser):
    """Base parser for BPMSoft text logs with stacktrace continuations."""

    name = "bpmsoft_text"
    marker_patterns: tuple[re.Pattern[str], ...] = ()
    default_component = "bpmsoft"

    def __init__(self) -> None:
        self._delegate = TextMultilineParser()

    def can_parse(self, sample: str) -> float:
        base_score = self._delegate.can_parse(sample)
        if base_score <= 0:
            return 0.0
        marker_hit = any(pattern.search(sample) for pattern in self.marker_patterns)
        if marker_hit:
            return min(1.0, max(0.75, base_score + 0.15))
        return min(0.7, base_score)

    def parse(self, text: str, source: str | None = None) -> ParseResult:
        result = self._delegate.parse(text, source=source)
        for event in result.events:
            event.parser_name = self.name
            event.parser_confidence = clamp_confidence(max(event.parser_confidence, 0.82))
            if not event.component:
                event.component = self.default_component
        return ParseResult(
            events=result.events,
            parser_name=self.name,
            confidence=clamp_confidence(max(result.confidence, 0.75)),
            stats=dict(result.stats),
            warnings=list(result.warnings),
        )


class BPMSoftErrorParser(_BPMSoftTextParser):
    """Parser for BPMSoft Error.log style multiline records."""

    name = "bpmsoft_error"
    marker_patterns = (
        re.compile(r"\b(ERROR|FATAL|Exception|BPMSoft)\b", re.IGNORECASE),
    )
    default_component = "error"


class BPMSoftBusinessProcessParser(_BPMSoftTextParser):
    """Parser for BPMSoft BusinessProcess.log style multiline records."""

    name = "bpmsoft_business_process"
    marker_patterns = (
        re.compile(r"\b(BusinessProcess|Process|BPMSoft\.Core|ProcessParameter)\b", re.IGNORECASE),
    )
    default_component = "business_process"


class BPMSoftAspNetCoreParser(_BPMSoftTextParser):
    """Parser for BPMSoft ASP.NET Core application logs."""

    name = "bpmsoft_aspnetcore"
    marker_patterns = (
        re.compile(r"\b(AspNetCore|Microsoft\.AspNetCore|Hosting|Kestrel|Request)\b", re.IGNORECASE),
    )
    default_component = "aspnetcore"
