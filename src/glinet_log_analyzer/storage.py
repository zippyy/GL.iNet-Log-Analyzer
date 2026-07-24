from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from .models import AnalysisResult, CellularReading, LogEntry, WifiClient


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


def delete_report(report_id: str) -> bool:
    """Delete a saved report. Returns True if deleted, False if not found."""
    report_path = get_reports_dir() / f"{report_id}.json"
    if not report_path.exists():
        return False
    report_path.unlink()
    return True


def list_reports() -> list[dict[str, Any]]:
    """List all saved reports sorted by modification time (newest first)."""
    reports_dir = get_reports_dir()
    reports: list[dict[str, Any]] = []
    for path in sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            reports.append({
                "report_id": payload["report_id"],
                "filename": payload["filename"],
                "total_lines": payload["result"]["summary"]["total_lines"],
                "created": path.stat().st_mtime,
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return reports[:50]


def _analysis_result_from_dict(payload: dict[str, Any]) -> AnalysisResult:
    entries = [_log_entry_from_dict(entry) for entry in payload["entries"]]
    notable_events = [_log_entry_from_dict(entry) for entry in payload["notable_events"]]
    timeline = [_log_entry_from_dict(entry) for entry in payload["timeline"]]
    summary = payload["summary"]

    wifi_clients = []
    for c in payload.get("wifi_clients", []):
        wifi_clients.append(WifiClient(
            mac=c["mac"], first_seen=c["first_seen"], last_seen=c["last_seen"],
            join_count=c.get("join_count", 0), leave_count=c.get("leave_count", 0),
            last_event=c.get("last_event", ""),
        ))

    cellular_readings = []
    for r in payload.get("cellular_readings", []):
        cellular_readings.append(CellularReading(
            timestamp=r["timestamp"], rsrp=r.get("rsrp"), rsrq=r.get("rsrq"), sinr=r.get("sinr"),
        ))

    return AnalysisResult(
        entries=entries,
        severity_counts=Counter(summary["severity_counts"]),
        category_counts=Counter(summary["category_counts"]),
        component_counts=Counter(summary["component_counts"]),
        signal_counts=Counter(summary["signal_counts"]),
        source_counts=Counter(summary["source_counts"]),
        notable_events=notable_events,
        timeline=timeline,
        wifi_clients=wifi_clients,
        cellular_readings=cellular_readings,
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
