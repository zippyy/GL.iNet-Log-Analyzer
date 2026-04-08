import gzip
import io
import os
import shutil
import unittest
import zipfile
from pathlib import Path

from glinet_log_analyzer.analyzer import analyze_documents, analyze_text
from glinet_log_analyzer.ingest import load_documents_from_bytes
from glinet_log_analyzer.reporting import entries_to_csv, filter_entries, format_text_report
from glinet_log_analyzer.storage import load_report, save_report


class AnalyzerTests(unittest.TestCase):
    def test_analyze_text_extracts_severity_and_categories(self) -> None:
        text = "\n".join(
            [
                "2026-04-03 10:14:00 netifd: wan link is up",
                "2026-04-03 10:15:01 hostapd: wlan0: AP-STA-CONNECTED 12:34:56:78:90:ab",
                "2026-04-03 10:15:22 dnsmasq[1]: failed to resolve api.example.com",
                "2026-04-03 10:16:11 dropbear[422]: Bad password attempt for root",
            ]
        )

        result = analyze_text(text)

        self.assertEqual(len(result.entries), 4)
        self.assertEqual(result.severity_counts["error"], 1)
        self.assertEqual(result.category_counts["wan"], 1)
        self.assertEqual(result.category_counts["wifi"], 1)
        self.assertEqual(result.category_counts["dns"], 1)
        self.assertEqual(result.category_counts["auth"], 1)
        self.assertEqual(result.component_counts["netifd"], 1)
        self.assertEqual(result.signal_counts["wan_up"], 1)
        self.assertEqual(result.signal_counts["wifi_client_join"], 1)
        self.assertEqual(result.signal_counts["dns_failure"], 1)
        self.assertEqual(result.signal_counts["auth_failure"], 1)
        self.assertEqual(len(result.timeline), 4)
        self.assertEqual(result.entries[0].source, "inline")

    def test_wifi_interfaces_like_wlan0_are_categorized(self) -> None:
        result = analyze_text("2026-04-03 10:15:01 hostapd: wlan0: AP-STA-CONNECTED 12:34:56:78:90:ab")

        self.assertEqual(result.category_counts["wifi"], 1)

    def test_glinet_style_signals_are_detected(self) -> None:
        text = "\n".join(
            [
                "2026-04-03 10:14:03 netifd: Interface 'wan' has lost the connection",
                "2026-04-03 10:16:20 wg0: WireGuard peer handshake established",
                "2026-04-03 10:18:10 firewall: dropped packet from 10.0.0.8 to 1.1.1.1",
                "2026-04-03 10:19:10 modemmanager: LTE modem registered on network",
                "2026-04-03 10:20:10 sysupgrade: firmware upgrade available",
                "2026-04-03 10:20:15 mwan3track: interface wan is offline",
                "2026-04-03 10:20:20 tetherd: usb0 tether interface is up",
                "2026-04-03 10:20:25 modemmanager: SIM card ready",
                "2026-04-03 10:20:30 modemmanager: RSRP -95 RSRQ -8 SINR 19",
            ]
        )

        result = analyze_text(text)

        self.assertEqual(result.signal_counts["wan_down"], 1)
        self.assertEqual(result.signal_counts["vpn_handshake"], 1)
        self.assertEqual(result.signal_counts["firewall_drop"], 1)
        self.assertEqual(result.signal_counts["modem_event"], 2)
        self.assertEqual(result.signal_counts["firmware_update"], 1)
        self.assertEqual(result.signal_counts["multiwan_failover"], 1)
        self.assertEqual(result.signal_counts["tethering_event"], 1)
        self.assertEqual(result.signal_counts["sim_event"], 1)
        self.assertEqual(result.signal_counts["cell_signal"], 1)

    def test_archive_ingest_supports_zip_and_gzip(self) -> None:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as archive:
            archive.writestr("logs/system.log", "2026-04-03 10:14:00 netifd: wan link is up\n")
            archive.writestr("logs/mwan3.log", "2026-04-03 10:14:03 mwan3track: interface wan is offline\n")

        zip_docs = load_documents_from_bytes("bundle.zip", zip_buffer.getvalue())
        zip_result = analyze_documents(zip_docs)

        gz_payload = gzip.compress(b"2026-04-03 10:16:20 wg0: WireGuard peer handshake established\n")
        gz_docs = load_documents_from_bytes("router.log.gz", gz_payload)
        gz_result = analyze_documents(gz_docs)

        self.assertEqual(len(zip_docs), 2)
        self.assertEqual(zip_result.signal_counts["wan_up"], 1)
        self.assertEqual(zip_result.signal_counts["multiwan_failover"], 1)
        self.assertEqual(gz_result.signal_counts["vpn_handshake"], 1)

    def test_reporting_filters_and_csv_export(self) -> None:
        result = analyze_text(
            "\n".join(
                [
                    "2026-04-03 10:14:03 mwan3track: interface wan is offline",
                    "2026-04-03 10:16:45 modemmanager: SIM card not inserted",
                    "2026-04-03 10:17:10 modemmanager: RSRP -95 RSRQ -8 SINR 19",
                ]
            )
        )
        filtered = filter_entries(result.entries, signal="sim_event")
        csv_text = entries_to_csv(filtered)

        self.assertEqual(len(filtered), 1)
        self.assertIn("SIM card not inserted", csv_text)
        self.assertEqual(result.signal_counts["multiwan_failover"], 1)
        self.assertEqual(result.signal_counts["sim_event"], 1)
        self.assertEqual(result.signal_counts["cell_signal"], 1)

    def test_reports_can_be_saved_and_loaded_from_disk(self) -> None:
        result = analyze_text("2026-04-03 10:16:53 modemmanager: SIM card ready")
        temp_dir = Path(".test-data")
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

        original = os.environ.get("GLINET_LOG_ANALYZER_DATA_DIR")
        os.environ["GLINET_LOG_ANALYZER_DATA_DIR"] = str(temp_dir)
        try:
            save_report("report-123", "router.log", result)
            loaded = load_report("report-123")
        finally:
            if original is None:
                del os.environ["GLINET_LOG_ANALYZER_DATA_DIR"]
            else:
                os.environ["GLINET_LOG_ANALYZER_DATA_DIR"] = original
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["filename"], "router.log")
        self.assertEqual(loaded["result"].signal_counts["sim_event"], 1)

    def test_syslog_style_lines_do_not_trigger_false_positive_cellular_or_wifi_signals(self) -> None:
        text = "\n".join(
            [
                "Tue Apr  7 15:42:35 2026 kern.err kernel: [ 5258.462851] wlan: [7166:I:ANY] DES SSID SET=GL-BE3600-446-5G",
                "Tue Apr  7 15:42:35 2026 kern.err kernel: [ 5258.555501] wlan: [0:I:CMN_MLME] Sending ucast disassoc to PMF associated stas",
                "Tue Apr  7 15:42:48 2026 kern.err kernel: [ 5270.795587] wlan: [0:I:CMN_MLME] vdev 2 cm_id 0xc020001: Connecting to GL-BE6500-d4f-MLO 8e:25:06:4a:ef:f3 rssi: -20 freq: 5200",
                "Tue Apr  7 15:42:48 2026 daemon.notice netifd: Interface 'wwan' is now up",
            ]
        )

        result = analyze_text(text)

        self.assertEqual(result.signal_counts["modem_event"], 0)
        self.assertEqual(result.signal_counts["wifi_client_join"], 0)
        self.assertEqual(result.signal_counts["cell_signal"], 0)
        self.assertEqual(result.category_counts["cellular"], 0)
        self.assertEqual(result.entries[0].timestamp, "Tue Apr  7 15:42:35 2026")
        self.assertEqual(result.entries[0].component, "kernel")
        self.assertEqual(result.entries[0].severity, "error")

    def test_format_text_report_is_human_readable(self) -> None:
        result = analyze_text(
            "\n".join(
                [
                    "2026-04-03 10:14:03 netifd: Interface 'wan' has lost the connection",
                    "2026-04-03 10:14:07 udhcpc: lease of 192.168.8.22 obtained from 192.168.8.1",
                    "2026-04-03 10:14:40 hostapd: wlan0: AP-STA-CONNECTED 12:34:56:78:90:ab",
                ]
            )
        )

        report = format_text_report(result, result.entries, file_label="sample.log")

        self.assertIn("GL.iNet log report for sample.log", report)
        self.assertIn("What stands out", report)
        self.assertIn("WAN connectivity dropped 1 time(s).", report)
        self.assertIn("Wi-Fi client churn detected: 1 join(s), 0 leave(s).", report)


if __name__ == "__main__":
    unittest.main()
