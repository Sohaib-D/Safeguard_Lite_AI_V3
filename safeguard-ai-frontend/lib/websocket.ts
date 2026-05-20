import { SOCMessage } from '../types';
import { useAppStore } from '../store/useAppStore';

const DEMO_ALERTS = [
  { id: 101, timestamp: new Date().toISOString(), type: 'SQL Injection', severity: 'critical', source_ip: '192.168.1.45', description: 'Multiple failed SQL injection attempts detected on login endpoint.', status: 'active' },
  { id: 102, timestamp: new Date().toISOString(), type: 'SSH Brute Force', severity: 'high', source_ip: '45.33.22.11', description: '100+ failed SSH login attempts in 5 minutes.', status: 'active' },
  { id: 103, timestamp: new Date().toISOString(), type: 'Port Scan', severity: 'medium', source_ip: '10.0.0.5', description: 'Sequential port scan detected across 500 ports.', status: 'active' },
  { id: 104, timestamp: new Date().toISOString(), type: 'Malware Signature', severity: 'critical', source_ip: '172.16.0.8', description: 'Known malware signature detected in HTTP payload.', status: 'active' },
  { id: 105, timestamp: new Date().toISOString(), type: 'DDoS Attempt', severity: 'high', source_ip: 'Multiple', description: 'Sudden spike in UDP traffic indicating possible amplification attack.', status: 'active' },
  { id: 106, timestamp: new Date().toISOString(), type: 'Data Exfiltration', severity: 'critical', source_ip: '10.0.0.50', description: 'Unusually large outbound data transfer to unknown IP.', status: 'active' }
];

export class WebSocketManager {
  private url: string;
  private token: string | null;
  private socket: WebSocket | null = null;
  private demoInterval: ReturnType<typeof setInterval> | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private isDemoMode = false;

  constructor() {
    const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
    this.url = apiBase.replace(/^http/, 'ws') + '/api/v1/ws/traffic';
    this.token = useAppStore.getState().authToken;
  }

  connect(onMessage: (msg: SOCMessage) => void, onStatusChange: (status: 'connected' | 'disconnected' | 'demo') => void): void {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.socket = new WebSocket(this.url);
      
      const timeoutId = setTimeout(() => {
        if (this.socket?.readyState !== WebSocket.OPEN) {
          console.warn("WebSocket connection timeout. Activating Demo Mode.");
          this.activateDemoMode(onMessage, onStatusChange);
        }
      }, 3000);

      this.socket.onopen = () => {
        clearTimeout(timeoutId);
        this.reconnectAttempts = 0;
        this.isDemoMode = false;
        this.clearDemoMode();
        onStatusChange('connected');
        
        // Authenticate
        if (this.token) {
          this.socket?.send(JSON.stringify({ type: 'auth', token: this.token }));
        }
      };

      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data as SOCMessage);
        } catch (e) {
          console.error("Failed to parse WS message", e);
        }
      };

      this.socket.onclose = () => {
        clearTimeout(timeoutId);
        if (!this.isDemoMode) {
          onStatusChange('disconnected');
          this.attemptReconnect(onMessage, onStatusChange);
        }
      };

      this.socket.onerror = (error) => {
        console.error("WebSocket Error:", error);
      };

    } catch (error) {
      console.error("WebSocket connection failed entirely. Activating Demo Mode.");
      this.activateDemoMode(onMessage, onStatusChange);
    }
  }

  private attemptReconnect(onMessage: (msg: SOCMessage) => void, onStatusChange: (status: 'connected' | 'disconnected' | 'demo') => void) {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const backoff = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
      console.log(`Reconnecting in ${backoff}ms...`);
      setTimeout(() => this.connect(onMessage, onStatusChange), backoff);
    } else {
      console.warn("Max reconnect attempts reached. Falling back to Demo Mode.");
      this.activateDemoMode(onMessage, onStatusChange);
    }
  }

  private activateDemoMode(onMessage: (msg: SOCMessage) => void, onStatusChange: (status: 'connected' | 'disconnected' | 'demo') => void) {
    if (this.isDemoMode) return;
    this.isDemoMode = true;
    onStatusChange('demo');
    
    // Simulate streaming events every 3 seconds
    this.demoInterval = setInterval(() => {
      const randomAlert = DEMO_ALERTS[Math.floor(Math.random() * DEMO_ALERTS.length)];
      onMessage({
        type: 'alert',
        data: { ...randomAlert, id: Date.now(), timestamp: new Date().toISOString() }
      });
      
      // Occasionally send a log
      if (Math.random() > 0.7) {
        onMessage({
          type: 'log',
          data: { timestamp: new Date().toISOString(), level: 'INFO', message: 'Demo mode active: simulated connection check.', source: 'demo-service' }
        });
      }
    }, 3000);
  }

  private clearDemoMode() {
    if (this.demoInterval) {
      clearInterval(this.demoInterval);
      this.demoInterval = null;
    }
  }

  disconnect(): void {
    this.clearDemoMode();
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}
