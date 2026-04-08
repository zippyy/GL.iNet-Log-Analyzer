from __future__ import annotations

import re
from collections import Counter

from .ingest import LogDocument
from .models import AnalysisResult, LogEntry

TIMESTAMP_PATTERNS = [
    re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$"
    ),
    re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(?P<rest>.*)$"
    ),
    re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$"
    ),
]

SEVERITY_PATTERNS = {
    "critical": re.compile(r"\b(?:critical|crit|kernel panic|panic)\b", re.IGNORECASE),
    "error": re.compile(r"\b(?:error|failed|failure|fatal|timed out|timeout)\b", re.IGNORECASE),
    "warning": re.compile(r"\b(?:warning|warn|degraded|retry|disconnected|offline)\b", re.IGNORECASE),
    "info": re.compile(r"\b(?:info|notice|connected|started|ready|completed|registered)\b", re.IGNORECASE),
    "debug": re.compile(r"\b(?:debug|trace|verbose)\b", re.IGNORECASE),
}

CATEGORY_PATTERNS = {
    "wan": re.compile(r"\b(?:wan|dhcp|pppoe|gateway|uplink)\b", re.IGNORECASE),
    "wifi": re.compile(r"\b(?:wifi|wlan\d*|radio|ssid|802\.11|hostapd)\b", re.IGNORECASE),
    "dns": re.compile(r"\b(?:dns|resolve|resolver|domain)\b", re.IGNORECASE),
    "firewall": re.compile(r"\b(?:firewall|iptables|nft|blocked|drop(?:ped)?)\b", re.IGNORECASE),
    "vpn": re.compile(r"\b(?:vpn|wireguard|wg\d*|openvpn|tun\d*)\b", re.IGNORECASE),
    "system": re.compile(r"\b(?:syslog|kernel|cpu|memory|load|reboot|boot)\b", re.IGNORECASE),
    "auth": re.compile(r"\b(?:login|auth|password|ssh|dropbear|token)\b", re.IGNORECASE),
    "lan": re.compile(r"\b(?:lan|bridge|br-lan|switch|ethernet)\b", re.IGNORECASE),
    "cellular": re.compile(r"\b(?:modem|modemmanager|lte|nr5g|mbim|qmi|sim card|rsrp|rsrq|sinr)\b", re.IGNORECASE),
    "multiwan": re.compile(r"\b(?:mwan3|failover|load[- ]balanc|tracking)\b", re.IGNORECASE),
    "usb_tethering": re.compile(r"\b(?:tether|rndis|usb0|iphone|androidusb)\b", re.IGNORECASE),
}

COMPONENT_PATTERN = re.compile(r"^(?:(?P<component>[\w./-]+)(?:\[\d+\])?:\s+)(?P<message>.*)$")
SYSLOG_PREFIX_PATTERN = re.compile(
    r"^(?P<facility>[\w-]+)\.(?P<level>debug|info|notice|warn|warning|err|error|crit|critical)\s+(?P<rest>.*)$",
    re.IGNORECASE,
)

SIGNAL_PATTERNS = {
    "wan_up": re.compile(
        r"\b(?:wan link is up|interface ['\"]?wan['\"]?.*is up|network device ['\"]?wan['\"]? link is up|udhcpc: lease of)\b",
        re.IGNORECASE,
    ),
    "wan_down": re.compile(
        r"\b(?:lost the connection|wan link is down|network device ['\"]?wan['\"]? link is down|carrier lost|pppoe.*disconnected)\b",
        re.IGNORECASE,
    ),
    "dhcp_lease": re.compile(r"\b(?:lease of \d{1,3}(?:\.\d{1,3}){3}|dhcpack|dhcpoffer)\b", re.IGNORECASE),
    "wifi_client_join": re.compile(
        r"(?:\bAP-STA-CONNECTED\b|\bwlan\d+:\s+STA\s+[0-9a-f:]+\s+IEEE 802\.11:\s+associated\b)",
        re.IGNORECASE,
    ),
    "wifi_client_leave": re.compile(
        r"(?:\bAP-STA-DISCONNECTED\b|\bwlan\d+:\s+STA\s+[0-9a-f:]+\s+IEEE 802\.11:\s+(?:disassociated|deauthenticated)\b)",
        re.IGNORECASE,
    ),
    "dns_failure": re.compile(r"\b(?:failed to resolve|no servers could be reached|dns.*timed out)\b", re.IGNORECASE),
    "auth_failure": re.compile(r"\b(?:bad password|login failed|authentication failure|invalid password)\b", re.IGNORECASE),
    "vpn_handshake": re.compile(r"\b(?:wireguard peer handshake established|peer .* handshake|initialization sequence completed)\b", re.IGNORECASE),
    "firewall_drop": re.compile(r"\b(?:dropped|drop\b|reject\b|blocked by firewall)\b", re.IGNORECASE),
    "firmware_update": re.compile(r"\b(?:firmware|upgrade|sysupgrade|ota)\b", re.IGNORECASE),
    "modem_event": re.compile(
        r"\b(?:modem|modemmanager|sim card|lte modem|registered on network|qmi|mbim)\b",
        re.IGNORECASE,
    ),
    "multiwan_failover": re.compile(r"\b(?:mwan3.*(?:offline|online|hotplug)|failover|interface .* is offline)\b", re.IGNORECASE),
    "tethering_event": re.compile(r"\b(?:tether|rndis|usb0|iphone usb|androidusb)\b", re.IGNORECASE),
    "sim_event": re.compile(r"\b(?:sim card|sim not inserted|sim ready|pin required)\b", re.IGNORECASE),
    "cell_signal": re.compile(r"\b(?:rsrp|rsrq|sinr|signal quality)\b", re.IGNORECASE),
    "reboot": re.compile(r"\b(?:reboot|restarting system|booting linux)\b", re.IGNORECASE),
}

TIMELINE_SIGNALS = {
    "wan_up",
    "wan_down",
    "dhcp_lease",
    "wifi_client_join",
    "wifi_client_leave",
    "dns_failure",
    "auth_failure",
    "vpn_handshake",
    "firewall_drop",
    "firmware_update",
    "modem_event",
    "multiwan_failover",
    "tethering_event",
    "sim_event",
    "cell_signal",
    "reboot",
}


def analyze_text(text: str) -> AnalysisResult:
    return analyze_documents([LogDocument(source="inline", text=text)])


def analyze_documents(documents: list[LogDocument]) -> AnalysisResult:
    entries: list[LogEntry] = []
    severity_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    component_counts: Counter[str] = Counter()
    signal_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()

    for document in documents:
        if not document.text:
            continue
        source_counts[document.source] += 1
        for line_number, raw_line in enumerate(document.text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            timestamp, remainder = _extract_timestamp(line)
            syslog_severity, remainder = _extract_syslog_severity(remainder)
            component, message = _extract_component(remainder)
            severity = syslog_severity or _detect_severity(message)
            categories = _categorize(message)
            signals = _detect_signals(message)

            entry = LogEntry(
                line_number=line_number,
                raw=raw_line,
                source=document.source,
                timestamp=timestamp,
                severity=severity,
                component=component,
                message=message,
                categories=categories,
                signals=signals,
            )
            entries.append(entry)
            severity_counts[severity] += 1
            if component:
                component_counts[component] += 1
            for category in categories:
                category_counts[category] += 1
            for signal in signals:
                signal_counts[signal] += 1

    notable_events = [entry for entry in entries if _is_notable(entry)]
    timeline = [entry for entry in entries if _is_timeline_event(entry)]
    return AnalysisResult(
        entries=entries,
        severity_counts=severity_counts,
        category_counts=category_counts,
        component_counts=component_counts,
        signal_counts=signal_counts,
        source_counts=source_counts,
        notable_events=notable_events,
        timeline=timeline,
    )


def _extract_timestamp(line: str) -> tuple[str | None, str]:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.group("timestamp"), match.group("rest")
    return None, line


def _detect_severity(line: str) -> str:
    for severity, pattern in SEVERITY_PATTERNS.items():
        if pattern.search(line):
            return severity
    return "unknown"


def _extract_syslog_severity(line: str) -> tuple[str | None, str]:
    match = SYSLOG_PREFIX_PATTERN.match(line)
    if not match:
        return None, line

    level = match.group("level").lower()
    rest = match.group("rest")
    severity_map = {
        "critical": "critical",
        "crit": "critical",
        "error": "error",
        "err": "error",
        "warning": "warning",
        "warn": "warning",
        "notice": "info",
        "info": "info",
        "debug": "debug",
    }
    return severity_map.get(level, "unknown"), rest


def _extract_component(line: str) -> tuple[str | None, str]:
    match = COMPONENT_PATTERN.match(line)
    if not match:
        return None, line
    return match.group("component"), match.group("message")


def _categorize(message: str) -> list[str]:
    return [name for name, pattern in CATEGORY_PATTERNS.items() if pattern.search(message)]


def _detect_signals(message: str) -> list[str]:
    return [name for name, pattern in SIGNAL_PATTERNS.items() if pattern.search(message)]


def _is_notable(entry: LogEntry) -> bool:
    if entry.severity in {"critical", "error"}:
        return True
    if entry.signals:
        return True
    return bool({"vpn", "wan", "wifi", "auth", "firewall"} & set(entry.categories))


def _is_timeline_event(entry: LogEntry) -> bool:
    return bool(TIMELINE_SIGNALS & set(entry.signals))
