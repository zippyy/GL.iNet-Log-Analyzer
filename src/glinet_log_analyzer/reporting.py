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


def detect_anomalies(result: AnalysisResult) -> list[str]:
    """Detect unusual patterns that warrant investigation."""
    sc = result.signal_counts
    anomalies: list[str] = []

    total_entries = len(result.entries)
    if total_entries == 0:
        return anomalies

    # High error rate (>30% of entries are errors/critical)
    error_rate = (sc.get("critical", 0) + sc.get("error", 0)) / total_entries
    if error_rate > 0.3:
        anomalies.append(f"🚨 High error rate: {error_rate:.0%} of log entries are errors or critical — this is abnormal.")

    # Rapid WAN flapping (more than 5 drops)
    if sc["wan_down"] > 5:
        anomalies.append(f"🚨 WAN connection flapping: {sc['wan_down']} drops detected — the internet connection is highly unstable.")

    # Excessive DNS failures (>10)
    if sc["dns_failure"] > 10:
        anomalies.append(f"🚨 Severe DNS issues: {sc['dns_failure']} DNS failures — the ISP's DNS may be completely down.")

    # Auth brute force (>5 failed logins)
    if sc["auth_failure"] > 5:
        anomalies.append(f"🚨 Possible brute force attack: {sc['auth_failure']} failed login attempts — check for unauthorized access.")

    # Client churn (more leaves than joins, or >10 leave events)
    if sc["wifi_client_leave"] > 10:
        anomalies.append(f"⚠ High Wi-Fi client churn: {sc['wifi_client_leave']} devices disconnected — possible range or interference problem.")
    if sc["wifi_client_leave"] > sc.get("wifi_client_join", 0) * 2:
        anomalies.append("⚠ More devices leaving than joining — Wi-Fi network may be unstable.")

    # Frequent failover (>5)
    if sc["multiwan_failover"] > 5:
        anomalies.append(f"⚠ Excessive failover events ({sc['multiwan_failover']}) — the primary connection is unreliable.")

    # Cellular signal issues
    if result.cellular_readings:
        rsrp_vals = [r.rsrp for r in result.cellular_readings if r.rsrp is not None]
        if rsrp_vals and min(rsrp_vals) < -110:
            anomalies.append("⚠ Very poor cellular signal (RSRP < -110 dBm) — the modem may struggle to maintain a connection.")
        sinr_vals = [r.sinr for r in result.cellular_readings if r.sinr is not None]
        if sinr_vals and min(sinr_vals) < 0:
            anomalies.append("⚠ Negative SINR detected — cellular signal quality is critically poor.")

    # Repeater instability
    if sc["repeater_switch"] > 3:
        anomalies.append(f"⚠ Repeater instability: switched networks {sc['repeater_switch']} times — may indicate weak signal or competing APs.")

    return anomalies


def build_narrative_timeline(result: AnalysisResult) -> list[dict[str, str]]:
    """Build a human-readable timeline with relative timestamps and severity colors."""
    timeline: list[dict[str, str]] = []
    prev_time: str | None = None

    for entry in result.timeline[:30]:
        when = entry.timestamp or ""
        narratives = []
        severity = "neutral"
        for signal in entry.signals:
            narratives.append(SIGNAL_NARRATIVES.get(signal, signal.replace("_", " ")))
            if signal in ("wan_down", "wan_up", "wifi_client_leave", "multiwan_failover",
                          "wwan_down", "wwan_up", "repeater_switch"):
                severity = "warn"
            if signal in ("dns_failure", "auth_failure", "reboot", "firewall_drop"):
                severity = "error"
        if not narratives:
            narratives.append(entry.message[:100])

        # Relative time
        if when and prev_time:
            delta = _time_diff(prev_time, when)
            display_time = f"{when} ({delta})" if delta else when
        else:
            display_time = when or ""
        prev_time = when

        timeline.append({
            "time": display_time,
            "what": " | ".join(narratives),
            "severity": severity,
        })
    return timeline


def _time_diff(t1: str, t2: str) -> str:
    """Return a human-readable difference between two timestamp strings."""
    # Try common formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S"):
        try:
            from datetime import datetime as dt
            d1 = dt.strptime(t1.rsplit(".", 1)[0] if "." in t1 else t1, fmt)
            d2 = dt.strptime(t2.rsplit(".", 1)[0] if "." in t2 else t2, fmt)
            diff = (d2 - d1).total_seconds()
            if diff < 0:
                return ""
            if diff < 1:
                return "<1s later"
            if diff < 60:
                return f"{int(diff)}s later"
            if diff < 3600:
                m = int(diff // 60)
                s = int(diff % 60)
                return f"{m}m{s}s later" if s else f"{m}m later"
            h = int(diff // 3600)
            m = int((diff % 3600) // 60)
            return f"{h}h{m}m later" if m else f"{h}h later"
        except (ValueError, OverflowError):
            continue
    return ""


def generate_customer_summary(result: AnalysisResult) -> str:
    """Generate a non-technical summary suitable for sharing with the end customer."""
    sc = result.signal_counts
    lines: list[str] = []

    if sc["wan_down"]:
        lines.append(f"Your internet connection dropped briefly {sc['wan_down']} time(s).")
        if sc["wan_up"]:
            lines.append("It came back online automatically each time.")
    else:
        lines.append("Your internet connection appears stable.")

    if sc["wifi_client_join"] or sc["wifi_client_leave"]:
        lines.append(f"{sc['wifi_client_join']} device(s) connected to your Wi-Fi and {sc['wifi_client_leave']} disconnected.")

    if sc["dns_failure"]:
        lines.append("A few websites may have been temporarily unreachable due to a DNS hiccup — this is usually minor and self-resolving.")

    if not lines:
        lines.append("Everything looks normal — no issues were found in your router's logs.")

    return " ".join(lines)


def generate_root_cause(result: AnalysisResult) -> str:
    """Suggest the most likely root cause based on observed patterns."""
    sc = result.signal_counts

    if sc["wan_down"] >= 1 and sc["dhcp_lease"] >= 1:
        return "💡 The combination of WAN drops and DHCP lease renewals suggests the ISP modem or upstream connection was briefly interrupted (possibly a modem reboot or ISP flap)."
    if sc["dns_failure"] > 3:
        return "💡 Multiple DNS failures point to an issue with the ISP's DNS servers. This is a common cause of 'websites not loading' complaints. Try switching to Cloudflare (1.1.1.1) or Google (8.8.8.8) DNS."
    if sc["auth_failure"] > 3:
        return "💡 Multiple failed login attempts suggest someone (or a bot) is trying to guess the router's password. Ensure remote admin access is disabled or protected with a strong password."
    if sc["repeater_switch"] > 2:
        return "💡 The repeater is frequently switching between access points, which usually means the signal is weak at its current location. Try moving it closer to the main router."
    if sc["multiwan_failover"] > 3:
        return "💡 Frequent connection switching indicates the primary internet source is unreliable. If using a cellular backup, check the signal strength."
    if sc["wifi_client_leave"] > sc.get("wifi_client_join", 0) * 2:
        return "💡 Devices are dropping off Wi-Fi more than they're connecting. This often points to Wi-Fi interference, range issues, or channel congestion."
    if sc["reboot"]:
        return "💡 The router rebooted unexpectedly — this could be a power issue, overheating, or a firmware bug."
    if sc["wwan_down"]:
        return "💡 The wireless WAN link dropped, which means the upstream network (the network this router is connecting to via Wi-Fi) went down or its signal weakened."

    return ""
