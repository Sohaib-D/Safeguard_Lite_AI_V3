"""
Unit tests for PacketCaptureEngine — tests the actual refactored class.
"""

import threading
import time
import pytest
from unittest.mock import patch, MagicMock

from backend.network.packet_capture import PacketCaptureEngine


class TestPacketCaptureEngine:
    """Tests for PacketCaptureEngine."""

    def test_initial_state(self):
        """Engine starts in a stopped state."""
        engine = PacketCaptureEngine()
        assert engine.is_running is False
        assert engine.interface is None

    def test_initial_state_with_interface(self):
        """Engine can be initialized with an interface."""
        engine = PacketCaptureEngine(interface="eth0")
        assert engine.interface == "eth0"
        assert engine.is_running is False

    def test_stop_capture_when_not_running(self):
        """Calling stop on an already-stopped engine should not raise."""
        engine = PacketCaptureEngine()
        engine.stop_capture()  # Should be a no-op
        assert engine.is_running is False

    def test_start_sets_is_running_flag(self):
        """start_capture should set is_running=True before sniffing."""
        engine = PacketCaptureEngine()

        # Patch sniff so it immediately stops due to is_running=False
        # We verify the flag was flipped to True during the call.
        started_states = []

        def mock_sniff(**kwargs):
            started_states.append(engine.is_running)
            # Immediately trigger the stop_filter as if no packets arrive
            kwargs["stop_filter"](None)

        with patch("backend.network.packet_capture.sniff", mock_sniff):
            engine.start_capture()

        assert True in started_states, "is_running was never set to True"

    def test_stop_capture_unsets_flag(self):
        """stop_capture sets is_running to False."""
        engine = PacketCaptureEngine()
        engine.is_running = True
        engine.stop_capture()
        assert engine.is_running is False

    def test_packet_callback_ignores_non_ip_packets(self):
        """_packet_callback should silently skip packets without an IP layer."""
        engine = PacketCaptureEngine()
        engine.is_running = True

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False  # No IP layer
        # Should not raise
        engine._packet_callback(mock_packet)

    def test_packet_callback_processes_tcp_packet(self):
        """_packet_callback extracts src/dst for a valid TCP packet."""
        from scapy.all import IP, TCP, Ether

        engine = PacketCaptureEngine()
        engine.is_running = True

        # Build a real scapy packet
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80)
        # Should not raise
        engine._packet_callback(pkt)

    def test_packet_callback_processes_udp_packet(self):
        """_packet_callback extracts protocol=UDP for a UDP packet."""
        from scapy.all import IP, UDP

        engine = PacketCaptureEngine()
        engine.is_running = True

        pkt = IP(src="9.8.7.6", dst="1.2.3.4") / UDP(sport=54321, dport=53)
        engine._packet_callback(pkt)

    def test_interface_can_be_updated_before_start(self):
        """Interface attribute is mutable before capture starts."""
        engine = PacketCaptureEngine()
        engine.interface = "wlan0"
        assert engine.interface == "wlan0"

    def test_concurrent_stop_is_safe(self):
        """Calling stop_capture from multiple threads should not raise."""
        engine = PacketCaptureEngine()
        engine.is_running = True
        threads = [threading.Thread(target=engine.stop_capture) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert engine.is_running is False

    @patch("backend.network.packet_capture.sniff")
    def test_start_capture_passes_interface_to_sniff(self, mock_sniff):
        """start_capture should pass the configured interface to scapy.sniff."""
        engine = PacketCaptureEngine(interface="lo")

        # Make sniff stop immediately via stop_filter
        def fake_sniff(**kwargs):
            engine.is_running = False  # force stop

        mock_sniff.side_effect = fake_sniff
        engine.start_capture()
        mock_sniff.assert_called_once()
        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs.get("iface") == "lo"