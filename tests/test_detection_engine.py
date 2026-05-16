"""Unit tests for the network detection components (ConnectionTracker, DNSMonitor, TrafficAnalyzer, LiveDetectionEngine)."""

import asyncio
import time
import pytest

from backend.network.connection_tracker import ConnectionTracker, ConnectionEvent
from backend.network.dns_monitor import DNSMonitor
from backend.network.traffic_analyzer import TrafficAnalyzer
from backend.network.live_detection_engine import LiveDetectionEngine


# ─────────────────────────────────────────────
# ConnectionTracker Tests
# ─────────────────────────────────────────────

class TestConnectionTracker:
    def test_no_alert_for_normal_traffic(self):
        tracker = ConnectionTracker()
        event = ConnectionEvent(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol="TCP",
            timestamp=time.time(),
        )
        alerts = tracker.track(event)
        assert isinstance(alerts, list)
        # A single connection should not trigger any alert
        assert len(alerts) == 0

    def test_brute_force_detection(self):
        tracker = ConnectionTracker(brute_force_threshold=3)
        for _ in range(3):
            event = ConnectionEvent(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                dst_port=22,
                protocol="TCP",
                timestamp=time.time(),
                is_auth_failure=True,
            )
            alerts = tracker.track(event)

        # After reaching threshold, at least one brute-force alert should fire
        assert any("Brute Force" in a for a in alerts)

    def test_rapid_connection_spike_detection(self):
        tracker = ConnectionTracker(brute_force_threshold=2)
        # brute_force_threshold * 4 = 8 connections triggers spike alert
        alerts = []
        for _ in range(9):
            event = ConnectionEvent(
                src_ip="10.0.0.5",
                dst_ip="10.0.0.2",
                dst_port=443,
                protocol="TCP",
                timestamp=time.time(),
            )
            alerts = tracker.track(event)

        assert any("Traffic Spike" in a for a in alerts)


# ─────────────────────────────────────────────
# DNSMonitor Tests
# ─────────────────────────────────────────────

class TestDNSMonitor:
    def test_suspicious_tld_triggers_alert(self):
        monitor = DNSMonitor()
        alerts = monitor.analyze_query("192.168.1.5", "badsite.xyz")
        assert len(alerts) >= 1
        assert any("Suspicious Domain" in a for a in alerts)

    def test_long_domain_triggers_alert(self):
        monitor = DNSMonitor()
        long_domain = "a" * 61 + ".com"
        alerts = monitor.analyze_query("192.168.1.10", long_domain)
        assert any("Long Domain" in a for a in alerts)

    def test_normal_domain_no_alert(self):
        monitor = DNSMonitor()
        alerts = monitor.analyze_query("192.168.1.1", "google.com")
        assert len(alerts) == 0

    def test_high_dns_rate_triggers_alert(self):
        # Set a very low threshold so we can trigger it quickly
        monitor = DNSMonitor(rate_threshold=2)
        for i in range(3):
            alerts = monitor.analyze_query("192.168.1.2", f"example{i}.com")
        assert any("High DNS Rate" in a for a in alerts)


# ─────────────────────────────────────────────
# TrafficAnalyzer Tests
# ─────────────────────────────────────────────

class TestTrafficAnalyzer:
    def test_normal_traffic_no_alert(self):
        analyzer = TrafficAnalyzer(max_bytes_per_window=100_000_000)
        alerts = analyzer.analyze("10.0.0.1", "10.0.0.2", 1000)
        assert len(alerts) == 0

    def test_high_volume_triggers_alert(self):
        # Set a tiny threshold
        analyzer = TrafficAnalyzer(max_bytes_per_window=100)
        alerts = analyzer.analyze("10.0.0.1", "10.0.0.2", 200)
        assert any("High Data Volume" in a for a in alerts)


# ─────────────────────────────────────────────
# LiveDetectionEngine Tests
# ─────────────────────────────────────────────

class TestLiveDetectionEngine:
    @pytest.mark.asyncio
    async def test_engine_processes_valid_packet(self):
        """Engine should process a valid packet without raising exceptions."""
        engine = LiveDetectionEngine()
        packet_data = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 80,
            "length": 512,
            "timestamp_val": time.time(),
        }
        # Should not raise
        await engine.process_packet(packet_data)

    @pytest.mark.asyncio
    async def test_engine_ignores_packet_without_ips(self):
        """Engine should silently skip packets missing src/dst IPs."""
        engine = LiveDetectionEngine()
        bad_packet = {"protocol": "TCP", "length": 100}
        # Should return early without raising
        await engine.process_packet(bad_packet)

    @pytest.mark.asyncio
    async def test_callback_is_invoked_on_alert(self):
        """When a suspicious packet triggers an alert, the registered callback fires."""
        engine = LiveDetectionEngine()
        fired_alerts = []

        async def capture_alert(alert):
            fired_alerts.append(alert)

        engine.add_callback(capture_alert)

        # Send many auth-failure TCP RST events on SSH port to trigger brute-force
        # Override tracker threshold for speed
        engine.conn_tracker = ConnectionTracker(brute_force_threshold=2)
        for _ in range(2):
            event = ConnectionEvent(
                src_ip="10.0.0.99",
                dst_ip="10.0.0.1",
                dst_port=22,
                protocol="TCP",
                timestamp=time.time(),
                is_auth_failure=True,
            )
            engine.conn_tracker.track(event)

        # Now send via process_packet which routes through the tracker
        # The brute force alert will only fire from within the tracker; we
        # check the callback is callable by hooking a DNS alert instead.
        fired_alerts.clear()
        packet_data = {
            "src_ip": "10.0.0.99",
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "dst_port": 53,
            "length": 80,
            "timestamp_val": time.time(),
            "dns_query": "malware.xyz",  # Suspicious TLD -> alert
        }
        await engine.process_packet(packet_data)
        assert len(fired_alerts) >= 1
        assert fired_alerts[0]["type"] == "live_alert"
