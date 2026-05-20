import { useEffect, useRef, useState } from 'react';
import { WebSocketManager } from '../lib/websocket';
import { useAppStore } from '../store/useAppStore';

export function useWebSocket() {
  const [status, setStatus] = useState<'connected' | 'disconnected' | 'demo'>('disconnected');
  const managerRef = useRef<WebSocketManager | null>(null);
  const appendLiveEvent = useAppStore(state => state.appendLiveEvent);

  useEffect(() => {
    managerRef.current = new WebSocketManager();
    
    managerRef.current.connect(
      (msg) => {
        if (msg.type === 'alert' || msg.type === 'log' || msg.type === 'notification') {
          appendLiveEvent({
            timestamp: msg.data.timestamp,
            type: msg.type,
            details: msg.data.message || msg.data.description || 'Unknown event',
            severity: msg.data.severity || msg.data.level || 'info'
          });
        }
      },
      (newStatus) => {
        setStatus(newStatus);
      }
    );

    return () => {
      if (managerRef.current) {
        managerRef.current.disconnect();
      }
    };
  }, [appendLiveEvent]);

  return { status };
}
