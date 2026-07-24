from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class LogEntry:
    line_number: int
    raw: str
    source: str | None
    timestamp: str | None
    severity: str
    component: str | None
    message: str
    categories: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WifiClient:
    mac: str
    first_seen: str
    last_seen: str
    join_count: int = 0
    leave_count: int = 0
    last_event: str = ""


@dataclass(slots=True)
class CellularReading:
    timestamp: str
    rsrp: int | None = None
    rsrq: int | None = None
    sinr: int | None = None


@dataclass(slots=True)
class AnalysisResult:
    entries: list[LogEntry]
    severity_counts: Counter[str]
    category_counts: Counter[str]
    component_counts: Counter[str]
    signal_counts: Counter[str]
    source_counts: Counter[str]
    notable_events: list[LogEntry]
    timeline: list[LogEntry]
    wifi_clients: list[WifiClient] = field(default_factory=list)
    cellular_readings: list[CellularReading] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_lines": len(self.entries),
                "severity_counts": dict(self.severity_counts),
                "category_counts": dict(self.category_counts),
                "component_counts": dict(self.component_counts),
                "signal_counts": dict(self.signal_counts),
                "source_counts": dict(self.source_counts),
                "notable_events": len(self.notable_events),
                "timeline_events": len(self.timeline),
            },
            "notable_events": [entry.to_dict() for entry in self.notable_events],
            "timeline": [entry.to_dict() for entry in self.timeline],
            "entries": [entry.to_dict() for entry in self.entries],
            "wifi_clients": [{"mac": c.mac, "first_seen": c.first_seen, "last_seen": c.last_seen, "join_count": c.join_count, "leave_count": c.leave_count, "last_event": c.last_event} for c in self.wifi_clients],
            "cellular_readings": [{"timestamp": r.timestamp, "rsrp": r.rsrp, "rsrq": r.rsrq, "sinr": r.sinr} for r in self.cellular_readings],
        }
