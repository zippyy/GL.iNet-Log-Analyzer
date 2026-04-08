from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import AnalysisResult, LogEntry


def get_data_dir() -> Path:
    root = Path(os.getenv("GLINET_LOG_ANALYZER_DATA_DIR", "data"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_reports_dir() -> Path:
    reports_dir = get_data_dir() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def save_report(report_id: str, filename: str, result: AnalysisResult) -> None:
    payload = {
        "report_id": report_id,
        "filename": filename,
        "result": result.to_dict(),
    }
    report_path = get_reports_dir() / f"{report_id}.json"
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_report(report_id: str) -> dict[str, Any] | None:
    report_path = get_reports_dir() / f"{report_id}.json"
    if not report_path.exists():
        return None
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "report_id": payload["report_id"],
        "filename": payload["filename"],
        "result": _analysis_result_from_dict(payload["result"]),
    }


def _analysis_result_from_dict(payload: dict[str, Any]) -> AnalysisResult:
    entries = [_log_entry_from_dict(entry) for entry in payload["entries"]]
    notable_events = [_log_entry_from_dict(entry) for entry in payload["notable_events"]]
    timeline = [_log_entry_from_dict(entry) for entry in payload["timeline"]]
    summary = payload["summary"]
    return AnalysisResult(
        entries=entries,
        severity_counts=summary["severity_counts"],
        category_counts=summary["category_counts"],
        component_counts=summary["component_counts"],
        signal_counts=summary["signal_counts"],
        source_counts=summary["source_counts"],
        notable_events=notable_events,
        timeline=timeline,
    )


def _log_entry_from_dict(payload: dict[str, Any]) -> LogEntry:
    return LogEntry(
        line_number=payload["line_number"],
        raw=payload["raw"],
        source=payload.get("source"),
        timestamp=payload["timestamp"],
        severity=payload["severity"],
        component=payload["component"],
        message=payload["message"],
        categories=payload.get("categories", []),
        signals=payload.get("signals", []),
    )
