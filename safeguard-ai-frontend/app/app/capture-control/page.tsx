"use client";

import { useEffect, useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { captureAPI } from "../../../lib/api";
import { Server, Play, Square, RefreshCw, Activity } from "lucide-react";
import { cn } from "../../../lib/utils";

export default function CaptureControlPage() {
  const [stats, setStats] = useState<any>(null);
  const [interfaceName, setInterfaceName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    try {
      setError(null);
      const res = await captureAPI.getStats();
      setStats(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Could not load capture status.");
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const startCapture = async () => {
    setLoading(true);
    try {
      setError(null);
      const res = await captureAPI.start(interfaceName.trim() || undefined);
      setStats((prev: any) => ({ ...prev, running: true, interface: res.interface }));
      await loadStats();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Could not start packet capture. Administrator privileges or a valid interface may be required.");
    } finally {
      setLoading(false);
    }
  };

  const stopCapture = async () => {
    setLoading(true);
    try {
      setError(null);
      await captureAPI.stop();
      setStats((prev: any) => ({ ...prev, running: false }));
      await loadStats();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Could not stop packet capture.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2 flex items-center gap-2">
            <Server className="w-6 h-6 text-accent-cyan" /> Capture Control
          </h1>
          <p className="text-text-secondary">Manage packet capture services and interfaces.</p>
        </div>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <section className="lg:col-span-2 bg-bg-secondary border border-border-subtle rounded-xl p-6">
            <div className="flex items-center justify-between gap-4 border-b border-border-subtle pb-4 mb-6">
              <div>
                <h2 className="font-bold text-text-primary">Capture Engine</h2>
                <p className="text-sm text-text-secondary">Controls the backend packet capture worker.</p>
              </div>
              <div className={cn(
                "px-3 py-1 rounded-full text-sm font-bold border",
                stats?.running ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-bg-tertiary text-text-secondary border-border-subtle"
              )}>
                {stats?.running ? "Running" : "Stopped"}
              </div>
            </div>

            <div className="flex flex-col md:flex-row gap-4">
              <input
                value={interfaceName}
                onChange={(e) => setInterfaceName(e.target.value)}
                placeholder="Interface name (optional, default if empty)"
                className="flex-1 px-4 py-3 bg-bg-primary border border-border-subtle rounded-lg text-text-primary focus:outline-none focus:border-accent-cyan"
              />
              <button
                onClick={startCapture}
                disabled={loading || stats?.running}
                className="px-5 py-3 bg-emerald-500 hover:bg-emerald-500/90 text-bg-primary font-bold rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <Play className="w-5 h-5" /> Start
              </button>
              <button
                onClick={stopCapture}
                disabled={loading || !stats?.running}
                className="px-5 py-3 bg-rose-500 hover:bg-rose-500/90 text-white font-bold rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <Square className="w-5 h-5" /> Stop
              </button>
              <button
                onClick={loadStats}
                disabled={loading}
                className="p-3 bg-bg-tertiary hover:bg-bg-primary border border-border-subtle rounded-lg text-text-secondary"
                title="Refresh status"
              >
                <RefreshCw className={cn("w-5 h-5", loading && "animate-spin")} />
              </button>
            </div>
          </section>

          <section className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
            <h2 className="font-bold text-text-primary mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5 text-accent-cyan" /> Current Stats
            </h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between gap-3"><span className="text-text-secondary">Interface</span><span className="text-text-primary">{stats?.interface || "Default"}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-secondary">Queued packets</span><span className="text-text-primary">{stats?.queue_size ?? 0}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-secondary">Flows</span><span className="text-text-primary">{stats?.flows_count ?? 0}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-secondary">Unique IPs</span><span className="text-text-primary">{stats?.ip_count ?? 0}</span></div>
            </div>
          </section>
        </div>
      </div>
    </AuthGuard>
  );
}
