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
    "repeater_connect": "Repeater connected to AP",
    "repeater_scan": "Repeater Wi-Fi scan",
    "repeater_switch": "Repeater switching AP",
    "cloud_mqtt": "GoodCloud MQTT activity",
    "wwan_up": "Wireless WAN came up",
    "wwan_down": "Wireless WAN went down",
}

CATEGORY_LABELS = {
    "wan": "WAN",
    "wifi": "Wi-Fi",
    "dns": "DNS",
    "firewall": "Firewall",
    "vpn": "VPN",
    "system": "System",
    "auth": "Authentication",
    "lan": "LAN",
    "cellular": "Cellular",
    "multiwan": "Multi-WAN",
    "usb_tethering": "USB Tethering",
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "error": "Error",
    "warning": "Warning",
    "info": "Info",
    "debug": "Debug",
    "unknown": "Unknown",
}


def format_text_report(result: AnalysisResult, filtered_entries: list[LogEntry], *, file_label: str) -> str:
    lines: list[str] = []
    lines.append(f"GL.iNet log report for {file_label}")
    lines.append("")
    lines.extend(_summary_lines(result, filtered_entries))
    lines.append("")
    lines.append("What stands out")
    findings = _key_findings(result, filtered_entries)
    if findings:
        for finding in findings:
            lines.append(f"- {finding}")
    else:
        lines.append("- No notable events matched the current detection rules.")

    lines.append("")
    lines.append("Representative events")
    sample_events = result.timeline[:8] if result.timeline else filtered_entries[:8]
    if sample_events:
        for entry in sample_events:
            signal_text = ", ".join(SIGNAL_LABELS.get(signal, signal.replace("_", " ")) for signal in entry.signals) or "General event"
            when = entry.timestamp or f"line {entry.line_number}"
            lines.append(f"- {when}: {signal_text}. {entry.message}")
    else:
        lines.append("- No events available after filtering.")

    if filtered_entries:
        lines.append("")
        lines.append("Recent lines to inspect")
        for entry in filtered_entries[:6]:
            when = entry.timestamp or f"line {entry.line_number}"
            lines.append(f"- {when}: {entry.message}")

    return "\n".join(lines)


def _summary_lines(result: AnalysisResult, filtered_entries: list[LogEntry]) -> list[str]:
    lines = [
        f"Entries parsed: {len(result.entries)} total, {len(filtered_entries)} shown by current filters.",
        f"Severity mix: {_format_counter(result.severity_counts, limit=4)}.",
        f"Main areas: {_format_counter(result.category_counts, limit=5)}.",
    ]
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


def _format_counter(counter: Counter[str], *, limit: int) -> str:
    items = [f"{name} {count}" for name, count in counter.most_common(limit)]
    return ", ".join(items) if items else "none"


# ── Support-agent narrative helpers ──────────────────────────────────────────

SIGNAL_NARRATIVES = {
    "wan_down": "WAN connection dropped — router lost internet",
    "wan_up": "WAN connection restored — internet is back",
    "dhcp_lease": "Device requested an IP address from the router",
    "wifi_client_join": "Wi-Fi device connected to the router",
    "wifi_client_leave": "Wi-Fi device disconnected from the router",
    "dns_failure": "DNS lookup failed — a website or service couldn't be reached",
    "auth_failure": "Someone tried to log in with the wrong password",
    "vpn_handshake": "VPN tunnel established",
    "firewall_drop": "Router blocked incoming traffic (normal firewall behavior)",
    "firmware_update": "Firmware update activity detected",
    "modem_event": "Cellular modem status changed",
    "multiwan_failover": "Router switched between internet connections",
    "tethering_event": "USB tethering device connected",
    "sim_event": "SIM card status changed",
    "cell_signal": "Cellular signal strength reading recorded",
    "reboot": "Router rebooted",
    "repeater_connect": "Repeater connected to a Wi-Fi network",
    "repeater_scan": "Repeater scanned for nearby networks",
    "repeater_switch": "Repeater switched to a different network",
    "cloud_mqtt": "Router contacted GoodCloud management service",
    "wwan_up": "Wireless WAN (repeater link) came online",
    "wwan_down": "Wireless WAN (repeater link) went offline",
}

def generate_verdict(result: AnalysisResult) -> str:
    """Plain-English summary of what happened in the log, for support agents."""
    sc = result.signal_counts
    parts: list[str] = []

    # WAN health
    if sc["wan_down"] and sc["wan_up"]:
        parts.append(f"The router experienced {sc['wan_down']} WAN outage(s) and recovered {sc['wan_up']} time(s).")
    elif sc["wan_down"]:
        parts.append(f"⚠ The router had {sc['wan_down']} WAN outage(s) with no recovery seen in this log.")
    elif sc["wan_up"]:
        parts.append("The WAN connection appears stable — no outages detected.")
    elif not sc["wan_down"] and not sc["wan_up"]:
        parts.append("No WAN state changes detected in this log.")

    # Wi-Fi clients
    if sc["wifi_client_join"] or sc["wifi_client_leave"]:
        parts.append(f"{sc['wifi_client_join']} device(s) connected to Wi-Fi, {sc['wifi_client_leave']} disconnected.")
    else:
        parts.append("No Wi-Fi client activity detected.")

    # DNS
    if sc["dns_failure"]:
        parts.append(f"⚠ {sc['dns_failure']} DNS lookup failure(s) — customers may report websites not loading.")

    # Auth
    if sc["auth_failure"]:
        parts.append(f"⚠ {sc['auth_failure']} failed login attempt(s) — possible unauthorized access attempts.")

    # Firewall
    if sc["firewall_drop"] > 5:
        parts.append(f"Firewall blocked traffic {sc['firewall_drop']} times — higher than typical.")

    # Cellular
    if sc["modem_event"] or sc["sim_event"]:
        parts.append(f"Cellular modem activity detected ({sc['modem_event']} event(s), {sc['sim_event']} SIM event(s)).")

    # VPN
    if sc["vpn_handshake"]:
        parts.append(f"VPN tunnel active — {sc['vpn_handshake']} handshake(s) seen.")

    # Repeater
    if sc["repeater_connect"]:
        parts.append(f"Repeater successfully connected to an upstream network {sc['repeater_connect']} time(s).")

    # Multi-WAN / failover
    if sc["multiwan_failover"]:
        parts.append(f"The router switched between connections {sc['multiwan_failover']} time(s) — customer may have noticed brief interruption.")

    # Reboot
    if sc["reboot"]:
        parts.append(f"⚠ Router rebooted {sc['reboot']} time(s).")

    # Overall assessment
    severity = _assess_health(sc)

    return f"{severity}\n\n" + " ".join(parts)


def _assess_health(sc: Counter[str]) -> str:
    issues = 0
    if sc["wan_down"] > sc.get("wan_up", 0):
        issues += 1
    if sc["dns_failure"] > 3:
        issues += 1
    if sc["auth_failure"] > 2:
        issues += 1
    if sc["reboot"]:
        issues += 1
    if sc["wwan_down"] > sc.get("wwan_up", 0):
        issues += 1

    if issues == 0:
        return "✅ Overall: Router appears healthy — no significant issues found."
    elif issues == 1:
        return "⚠ Overall: One potential issue detected — review details below."
    else:
        return "🚨 Overall: Multiple issues detected — this router needs attention."


def generate_triage_notes(result: AnalysisResult) -> list[str]:
    """Actionable triage guidance for support agents based on detected signals."""
    sc = result.signal_counts
    notes: list[str] = []

    if sc["wan_down"]:
        notes.append("Ask the customer if they noticed internet dropping. Check if the ISP modem was rebooted or if the Ethernet cable is loose.")
    if sc["dns_failure"]:
        notes.append("DNS failures can be caused by the ISP's DNS server. Try switching the router to use 1.1.1.1 or 8.8.8.8 as DNS.")
    if sc["auth_failure"]:
        notes.append("Failed login attempts suggest someone is trying to access the router. Verify the admin password is strong and consider disabling remote admin access.")
    if sc["multiwan_failover"]:
        notes.append("Frequent failover events may indicate an unstable primary connection. Check if the customer is using multi-WAN or a backup cellular modem.")
    if sc["wifi_client_leave"] > sc.get("wifi_client_join", 0):
        notes.append("More devices disconnecting than connecting — possible Wi-Fi range or interference issue. Ask the customer about dead zones.")
    if sc["repeater_switch"]:
        notes.append("The repeater is jumping between networks. Check signal strength at the repeater's location and consider locking it to a specific AP.")
    if sc["reboot"]:
        notes.append("Unexpected reboots may indicate a power issue, overheating, or a firmware bug. Check the router's uptime and temperature if available.")
    if sc["wwan_down"]:
        notes.append("The wireless WAN (repeater) link dropped. The upstream network may have gone down or the signal is too weak.")
    if sc["firmware_update"]:
        notes.append("Firmware activity detected. Verify the router is running the latest stable firmware version.")

    return notes[:5]


def build_narrative_timeline(result: AnalysisResult) -> list[dict[str, str]]:
    """Build a human-readable timeline for the web UI — plain English, not raw log lines."""
    timeline: list[dict[str, str]] = []
    for entry in result.timeline[:20]:
        when = entry.timestamp or ""
        narratives = []
        for signal in entry.signals:
            narratives.append(SIGNAL_NARRATIVES.get(signal, signal.replace("_", " ")))
        if not narratives:
            narratives.append(entry.message[:100])

        timeline.append({
            "time": when,
            "what": " | ".join(narratives),
        })
    return timeline
