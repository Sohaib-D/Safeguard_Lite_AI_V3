"use client";

import { useEffect, useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { useWebSocket } from "../../../hooks/useWebSocket";
import { useAppStore } from "../../../store/useAppStore";
import { logsAPI } from "../../../lib/api";
import { AlertBadge } from "../../../components/ui/AlertBadge";
import { Radio, Wifi, WifiOff, Activity, RefreshCw, FileText } from "lucide-react";
import { cn } from "../../../lib/utils";

export default function LiveMonitorPage() {
  const { status } = useWebSocket();
  const { liveHistory } = useAppStore();
  const [logs, setLogs] = useState<any[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);

  const loadLogs = async () => {
    setLoadingLogs(true);
    try {
      const res = await logsAPI.getLogs(50);
      setLogs(Array.isArray(res) ? res : []);
    } catch (err) {
      console.error("Logs failed", err);
    } finally {
      setLoadingLogs(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div className="flex flex-col md:flex-row justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-text-primary mb-2 flex items-center gap-2">
              <Radio className="w-6 h-6 text-accent-cyan" /> Live Network Monitor
            </h1>
            <p className="text-text-secondary">Monitor backend websocket events and recent system logs.</p>
          </div>
          <div className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-bold w-fit",
            status === "connected" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" :
            status === "demo" ? "bg-accent-violet/10 border-accent-violet/20 text-accent-violet" :
            "bg-rose-500/10 border-rose-500/20 text-rose-400"
          )}>
            {status === "connected" ? <Wifi className="w-4 h-4" /> : status === "demo" ? <Activity className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
            {status.toUpperCase()}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section className="bg-bg-secondary border border-border-subtle rounded-xl overflow-hidden">
            <div className="p-4 border-b border-border-subtle bg-bg-tertiary flex items-center justify-between">
              <h2 className="font-bold text-text-primary flex items-center gap-2">
                <Activity className="w-5 h-5 text-accent-cyan" /> Live Event Stream
              </h2>
              <span className="text-sm text-text-secondary">{liveHistory.length} events</span>
            </div>
            <div className="h-[520px] overflow-y-auto p-4 space-y-3 scrollbar-thin">
              {liveHistory.length === 0 ? (
                <div className="h-full flex items-center justify-center text-text-secondary">
                  No websocket events received yet.
                </div>
              ) : liveHistory.slice().reverse().map((event, i) => (
                <div key={i} className="bg-bg-primary border border-border-subtle rounded-lg p-4">
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <span className="font-semibold text-text-primary">{event.type}</span>
                    <AlertBadge severity={event.severity} />
                  </div>
                  <p className="text-sm text-text-secondary">{event.details}</p>
                  <p className="text-xs text-text-secondary mt-2">{new Date(event.timestamp).toLocaleString()}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="bg-bg-secondary border border-border-subtle rounded-xl overflow-hidden">
            <div className="p-4 border-b border-border-subtle bg-bg-tertiary flex items-center justify-between">
              <h2 className="font-bold text-text-primary flex items-center gap-2">
                <FileText className="w-5 h-5 text-accent-amber" /> System Logs
              </h2>
              <button onClick={loadLogs} className="p-2 rounded-lg bg-bg-primary border border-border-subtle text-text-secondary" title="Refresh logs">
                <RefreshCw className={cn("w-4 h-4", loadingLogs && "animate-spin")} />
              </button>
            </div>
            <div className="h-[520px] overflow-y-auto p-4 space-y-3 scrollbar-thin">
              {logs.length === 0 ? (
                <div className="h-full flex items-center justify-center text-text-secondary">
                  No system logs available from the backend.
                </div>
              ) : logs.map((log, i) => (
                <div key={i} className="bg-bg-primary border border-border-subtle rounded-lg p-4">
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <span className="font-semibold text-text-primary">{log.source || log.level || "System"}</span>
                    <span className="text-xs text-text-secondary">{log.timestamp ? new Date(log.timestamp).toLocaleString() : "N/A"}</span>
                  </div>
                  <p className="text-sm text-text-secondary">{log.message || JSON.stringify(log)}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="bg-bg-secondary border border-border-subtle rounded-xl p-5">
          <div className="flex gap-3">
            <Radio className="w-5 h-5 text-accent-cyan shrink-0 mt-0.5" />
            <p className="text-sm text-text-secondary">
              This monitor shows events that the backend actually emits. If the stream is disconnected or empty, it does not invent traffic; start packet capture or generate predictions to populate live activity.
            </p>
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}
