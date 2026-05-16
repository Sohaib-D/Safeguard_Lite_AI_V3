import logging
from typing import List, Dict
from fastapi import WebSocket

logger = logging.getLogger("safeguard.services.ws")

class WebSocketManager:
    def __init__(self):
        # active_connections[user_id] = [WebSocket, ...]
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: Dict):
        """Send message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send WS message: {e}")
                # Ideally remove dead connections here
                
# Global instance for app-wide use
ws_manager = WebSocketManager()
