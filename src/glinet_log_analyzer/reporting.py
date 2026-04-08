from __future__ import annotations

import csv
import io

from .models import AnalysisResult, LogEntry


def filter_entries(
    entries: list[LogEntry],
    *,
    severity: str | None = None,
    category: str | None = None,
    signal: str | None = None,
    source_contains: str | None = None,
    query: str | None = None,
) -> list[LogEntry]:
    filtered = entries
    if severity:
        filtered = [entry for entry in filtered if entry.severity == severity]
    if category:
        filtered = [entry for entry in filtered if category in entry.categories]
    if signal:
        filtered = [entry for entry in filtered if signal in entry.signals]
    if source_contains:
        needle = source_contains.lower()
        filtered = [entry for entry in filtered if entry.source and needle in entry.source.lower()]
    if query:
        needle = query.lower()
        filtered = [
            entry
            for entry in filtered
            if needle in entry.message.lower()
            or needle in entry.raw.lower()
            or (entry.component and needle in entry.component.lower())
            or (entry.source and needle in entry.source.lower())
        ]
    return filtered


def entries_to_csv(entries: list[LogEntry]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["source", "line_number", "timestamp", "severity", "component", "categories", "signals", "message"])
    for entry in entries:
        writer.writerow(
            [
                entry.source or "",
                entry.line_number,
                entry.timestamp or "",
                entry.severity,
                entry.component or "",
                ",".join(entry.categories),
                ",".join(entry.signals),
                entry.message,
            ]
        )
    return buffer.getvalue()


def build_filter_options(result: AnalysisResult) -> dict[str, list[str]]:
    return {
        "severities": sorted(result.severity_counts.keys()),
        "categories": sorted(result.category_counts.keys()),
        "signals": sorted(result.signal_counts.keys()),
        "sources": sorted(result.source_counts.keys()),
    }
