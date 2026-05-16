from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.services.websocket_manager import ws_manager

router = APIRouter(tags=["Real-time"])

@router.websocket("/ws/traffic")
async def traffic_websocket(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and wait for client messages if needed
            data = await websocket.receive_text()
            # Handle client-to-server messages here if necessary
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
