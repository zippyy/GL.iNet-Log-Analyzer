from __future__ import annotations

import csv
import io
from collections import Counter

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


SIGNAL_LABELS = {
    "wan_up": "WAN came up",
    "wan_down": "WAN went down",
    "dhcp_lease": "DHCP lease activity",
    "wifi_client_join": "Wi-Fi client joined",
    "wifi_client_leave": "Wi-Fi client left",
    "dns_failure": "DNS failure",
    "auth_failure": "Authentication failure",
    "vpn_handshake": "VPN handshake",
    "firewall_drop": "Firewall dropped traffic",
    "firmware_update": "Firmware update activity",
    "modem_event": "Cellular modem event",
    "multiwan_failover": "Multi-WAN / failover event",
    "tethering_event": "USB tethering event",
    "sim_event": "SIM event",
    "cell_signal": "Cellular signal metric",
    "reboot": "Reboot event",
}


def format_text_report(result: AnalysisResult, filtered_entries: list[LogEntry], *, file_label: str) -> str:
    lines: list[str] = []
    lines.append(f"GL.iNet log report for {file_label}")
    lines.append("")
    lines.extend(_summary_lines(result, filtered_entries))
    lines.append("")
    lines.append("Agent brief")
    lines.extend(_agent_brief_lines(result, filtered_entries))
    lines.append("")
    lines.append("What stands out")
    findings = _key_findings(result, filtered_entries)
    if findings:
        for finding in findings:
            lines.append(f"- {finding}")
    else:
        lines.append("- No notable events matched the current detection rules.")

    lines.append("")
    lines.append("Timeline")
    sample_events = _timeline_events(result, filtered_entries)
    if sample_events:
        for entry in sample_events:
            signal_text = _describe_entry(entry)
            when = entry.timestamp or f"line {entry.line_number}"
            lines.append(f"- {when}: {signal_text}. {entry.message}")
    else:
        lines.append("- No events available after filtering.")

    if filtered_entries:
        lines.append("")
        lines.append("Evidence")
        for entry in _evidence_entries(result, filtered_entries):
            when = entry.timestamp or f"line {entry.line_number}"
            context = []
            if entry.component:
                context.append(entry.component)
            if entry.source and entry.source != "inline":
                context.append(entry.source)
            prefix = f"[{' | '.join(context)}] " if context else ""
            lines.append(f"- {when}: {prefix}{entry.message}")

    return "\n".join(lines)


def _summary_lines(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[str]:
    lines = [_scope_line(result, filtered_entries), f"Overall assessment: {_overall_assessment(result, filtered_entries)}."]
    if filtered_entries:
        lines.append(f"Severity mix in view: {_format_counter(_entry_counter(filtered_entries, 'severity'), limit=4)}.")
        lines.append(f"Main areas in view: {_format_counter(_count_values(filtered_entries, 'categories'), limit=5)}.")
    if result.timeline:
        first = result.timeline[0].timestamp or f"line {result.timeline[0].line_number}"
        last = result.timeline[-1].timestamp or f"line {result.timeline[-1].line_number}"
        lines.append(f"Timeline window: {first} through {last}.")
    return lines


def _key_findings(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[str]:
    findings: list[str] = []
    signal_counts = result.signal_counts

    if signal_counts["wan_down"]:
        findings.append(f"WAN connectivity dropped {signal_counts['wan_down']} time(s).")
    if signal_counts["wan_up"]:
        findings.append(f"WAN connectivity recovered {signal_counts['wan_up']} time(s).")
    if signal_counts["dhcp_lease"]:
        findings.append(f"DHCP activity appeared {signal_counts['dhcp_lease']} time(s), which usually indicates client renewals or new leases.")
    if signal_counts["wifi_client_join"] or signal_counts["wifi_client_leave"]:
        findings.append(
            "Wi-Fi client churn detected: "
            f"{signal_counts['wifi_client_join']} join(s), {signal_counts['wifi_client_leave']} leave(s)."
        )
    if signal_counts["dns_failure"]:
        findings.append(f"DNS resolution failures detected {signal_counts['dns_failure']} time(s).")
    if signal_counts["auth_failure"]:
        findings.append(f"Authentication failures detected {signal_counts['auth_failure']} time(s).")
    if signal_counts["firewall_drop"]:
        findings.append(f"Firewall drop events detected {signal_counts['firewall_drop']} time(s).")
    if signal_counts["multiwan_failover"]:
        findings.append(f"Multi-WAN or failover behavior appeared {signal_counts['multiwan_failover']} time(s).")
    if signal_counts["modem_event"] or signal_counts["sim_event"] or signal_counts["cell_signal"]:
        findings.append(
            "Cellular activity detected: "
            f"{signal_counts['modem_event']} modem event(s), {signal_counts['sim_event']} SIM event(s), "
            f"{signal_counts['cell_signal']} signal reading(s)."
        )

    component_counts = Counter(entry.component for entry in filtered_entries if entry.component)
    if component_counts:
        component, count = component_counts.most_common(1)[0]
        findings.append(f"The busiest component in the filtered view is {component} with {count} line(s).")

    return findings[:8]


def _agent_brief_lines(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[str]:
    if not filtered_entries:
        return ["- No matching lines are visible in the current view."]

    lines = [
        f"- Filtered view contains {len(filtered_entries)} line(s) across {len({entry.source for entry in filtered_entries if entry.source}) or 1} source file(s).",
        f"- {len(result.timeline)} timeline event(s) and {len(result.notable_events)} notable event(s) were detected in the full analysis.",
    ]

    busiest_components = _entry_counter(filtered_entries, "component")
    if busiest_components:
        component, count = busiest_components.most_common(1)[0]
        lines.append(f"- The busiest component in this view is {component} with {count} line(s).")

    top_signal = _count_values(filtered_entries, "signals")
    if top_signal:
        signal, count = top_signal.most_common(1)[0]
        lines.append(f"- Most repeated signal in this view: {SIGNAL_LABELS.get(signal, signal.replace('_', ' '))} ({count}).")

    return lines


def _timeline_events(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[LogEntry]:
    filtered_ids = {id(entry) for entry in filtered_entries}
    filtered_timeline = [entry for entry in result.timeline if id(entry) in filtered_ids]
    if filtered_timeline:
        return filtered_timeline[:8]
    return filtered_entries[:8]


def _evidence_entries(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[LogEntry]:
    priority_entries = [entry for entry in filtered_entries if entry.signals or entry.severity in {"critical", "error", "warning"}]
    if priority_entries:
        return priority_entries[:6]
    if result.notable_events:
        return result.notable_events[:6]
    return filtered_entries[:6]


def _scope_line(result: AnalysisResult, filtered_entries: list[LogEntry]) -> str:
    total_entries = len(result.entries)
    visible_entries = len(filtered_entries)
    if visible_entries == total_entries:
        return f"Scope: showing the full analysis set with {visible_entries} parsed line(s)."
    hidden_entries = total_entries - visible_entries
    return f"Scope: showing {visible_entries} of {total_entries} parsed line(s); {hidden_entries} line(s) are hidden by the current filters."


def _overall_assessment(result: AnalysisResult, filtered_entries: list[LogEntry]) -> str:
    signal_counts = _count_values(filtered_entries, "signals")
    severity_counts = _entry_counter(filtered_entries, "severity")

    if signal_counts["wan_down"] or signal_counts["multiwan_failover"]:
        return "connectivity instability is the clearest issue in the visible log slice"
    if signal_counts["dns_failure"] or signal_counts["auth_failure"] or signal_counts["firewall_drop"]:
        return "user-facing failures are present and worth immediate inspection"
    if signal_counts["modem_event"] or signal_counts["sim_event"] or signal_counts["cell_signal"]:
        return "cellular activity dominates this log slice"
    if signal_counts["wifi_client_join"] or signal_counts["wifi_client_leave"]:
        return "the log is mostly showing Wi-Fi client activity rather than a clear fault"
    if severity_counts["critical"] or severity_counts["error"]:
        return "error-level events are present, but no stronger signal pattern dominates"
    if filtered_entries:
        return "the visible lines look mostly informational"
    if result.entries:
        return "the current filter set hides all parsed lines"
    return "no parsable log lines were found"


def _describe_entry(entry: LogEntry) -> str:
    if entry.signals:
        return ", ".join(SIGNAL_LABELS.get(signal, signal.replace("_", " ")) for signal in entry.signals)
    if entry.categories:
        return f"{', '.join(entry.categories)} activity"
    return "General event"


def _entry_counter(entries: list[LogEntry], attribute: str) -> Counter[str]:
    values = [value for entry in entries if (value := getattr(entry, attribute))]
    return Counter(values)


def _count_values(entries: list[LogEntry], attribute: str) -> Counter[str]:
    counter: Counter[str] = Counter()
    for entry in entries:
        counter.update(getattr(entry, attribute))
    return counter


def _format_counter(counter: Counter[str], *, limit: int) -> str:
    items = [f"{name} {count}" for name, count in counter.most_common(limit)]
    return ", ".join(items) if items else "none"
