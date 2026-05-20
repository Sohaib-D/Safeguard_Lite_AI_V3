"use client";

import { AuthGuard } from "../../../components/layout/AuthGuard";
import { useWebSocket } from "../../../hooks/useWebSocket";
import { useAppStore } from "../../../store/useAppStore";
import { MetricCard } from "../../../components/ui/MetricCard";
import { AlertBadge } from "../../../components/ui/AlertBadge";
import { ShieldAlert, Activity, Wifi, WifiOff, AlertTriangle, CheckCircle2 } from "lucide-react";
import { cn } from "../../../lib/utils";

export default function SOCDashboardPage() {
  const { status } = useWebSocket();
  const { liveHistory, authRole } = useAppStore();

  const isDemo = status === 'demo';
  const isConnected = status === 'connected';

  // Normalize severity comparison to be case-insensitive
  const alerts = liveHistory.filter(e => e.severity?.toLowerCase() === 'high' || e.severity?.toLowerCase() === 'critical');
  const criticalCount = liveHistory.filter(e => e.severity?.toLowerCase() === 'critical').length;
  const highCount = alerts.length - criticalCount;

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-border-subtle pb-6">
          <div>
            <h1 className="text-2xl font-bold text-text-primary mb-2 flex items-center gap-3">
              <ShieldAlert className="w-8 h-8 text-rose-500" />
              SOC Operations Dashboard
            </h1>
            <p className="text-text-secondary">Real-time threat monitoring and incident response.</p>
          </div>
          
          <div className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-bold",
            isConnected ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" :
            isDemo ? "bg-accent-violet/10 border-accent-violet/20 text-accent-violet" :
            "bg-rose-500/10 border-rose-500/20 text-rose-500"
          )}>
            {isConnected ? <Wifi className="w-4 h-4" /> : isDemo ? <Activity className="w-4 h-4 animate-pulse" /> : <WifiOff className="w-4 h-4" />}
            {isConnected ? "LIVE STREAM ACTIVE" : isDemo ? "AUTO DEMO MODE" : "DISCONNECTED"}
          </div>
        </div>

        {/* Real-time Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard 
            title="Total Events" 
            value={liveHistory.length} 
            className="border-accent-cyan/20 bg-accent-cyan/5" 
            valueClassName="text-accent-cyan"
          />
          <MetricCard 
            title="High Alerts" 
            value={highCount} 
            className="border-orange-500/20 bg-orange-500/5" 
            valueClassName="text-orange-500"
          />
          <MetricCard 
            title="Critical Threats" 
            value={criticalCount} 
            className="border-rose-500/20 bg-rose-500/5 shadow-[0_0_15px_rgba(244,63,94,0.1)]" 
            valueClassName="text-rose-500"
          />
          <MetricCard 
            title="System Status" 
            value="Nominal" 
            className="border-emerald-500/20 bg-emerald-500/5" 
            valueClassName="text-emerald-400 text-2xl"
          />
        </div>

        {/* Live Alert Feed */}
        <div className="bg-bg-secondary border border-border-subtle rounded-xl overflow-hidden flex flex-col h-[500px]">
          <div className="p-4 border-b border-border-subtle bg-bg-tertiary flex justify-between items-center">
            <h2 className="font-bold text-text-primary flex items-center gap-2">
              <Activity className="w-5 h-5 text-accent-cyan" /> Live Alert Stream
            </h2>
            <div className="flex gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500 animate-ping"></span>
            </div>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin">
            {liveHistory.length === 0 ? (
              <div className="h-full flex items-center justify-center text-text-secondary">
                Waiting for incoming events...
              </div>
            ) : (
              liveHistory.slice().reverse().map((event, i) => (
                <div key={i} className="bg-bg-primary border border-border-subtle rounded-lg p-4 flex flex-col sm:flex-row gap-4 animate-in slide-in-from-top-2">
                  <div className="flex flex-col gap-2 shrink-0 sm:w-48">
                    <span className="text-xs text-text-secondary font-mono">{new Date(event.timestamp).toLocaleTimeString()}</span>
                    <AlertBadge severity={event.severity} className="w-fit" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-bold text-text-primary text-sm sm:text-base mb-1">{event.type}</h4>
                    <p className="text-sm text-text-secondary">{event.details}</p>
                  </div>
                  <div className="shrink-0 flex items-center">
                    {authRole === 'admin' ? (
                      <button className="px-3 py-1.5 bg-bg-tertiary hover:bg-emerald-500/20 text-text-secondary hover:text-emerald-400 text-xs font-semibold rounded-lg border border-border-subtle transition-colors flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Acknowledge
                      </button>
                    ) : (
                      <span className="px-3 py-1.5 bg-bg-tertiary text-text-secondary text-xs rounded-lg border border-border-subtle">
                        View Only
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}
