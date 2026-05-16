import logging
import asyncio
from scapy.all import sniff, IP, TCP, UDP
from backend.services.websocket_manager import ws_manager

logger = logging.getLogger("safeguard.network.capture")

class PacketCaptureEngine:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.is_running = False

    def _packet_callback(self, packet):
        """Processes each captured packet."""
        if not packet.haslayer(IP):
            return

        # Basic Protocol mapping
        proto = "OTHER"
        if packet.haslayer(TCP): proto = "TCP"
        elif packet.haslayer(UDP): proto = "UDP"

        packet_data = {
            "timestamp": str(packet.time),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto,
            "len": len(packet)
        }
        
        # Broadcast via WebSockets for real-time visualization
        # In production, we would use an async queue to avoid blocking
        # loop = asyncio.get_event_loop()
        # loop.create_task(ws_manager.broadcast({"type": "traffic", "data": packet_data}))

    def start_capture(self):
        logger.info(f"Starting packet capture on {self.interface or 'default'}...")
        self.is_running = True
        sniff(
            iface=self.interface,
            prn=self._packet_callback,
            store=0,
            stop_filter=lambda x: not self.is_running
        )

    def stop_capture(self):
        logger.info("Stopping packet capture...")
        self.is_running = False
