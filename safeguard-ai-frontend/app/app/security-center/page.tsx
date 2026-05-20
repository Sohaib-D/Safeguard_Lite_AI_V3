"use client";

import { useState, useEffect } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { ShieldAlert, CheckCircle2, Search, RefreshCw } from "lucide-react";
import { DataTable } from "../../../components/ui/DataTable";
import { AlertBadge } from "../../../components/ui/AlertBadge";
import { alertsAPI } from "../../../lib/api";
import { useAppStore } from "../../../store/useAppStore";

export default function SecurityCenterPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const { authUser } = useAppStore();

  const fetchAlerts = async () => {
    setIsRefreshing(true);
    try {
      const res = await alertsAPI.getAlerts();
      setAlerts(res.alerts || []);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleAcknowledge = async (id: string) => {
    try {
      await alertsAPI.acknowledgeAlert(id);
      // Optimistically update UI
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "acknowledged", acknowledged: true } : a));
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  };

  const filteredAlerts = alerts.filter(a => 
    a.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.alert_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.src_ip?.includes(searchTerm)
  );

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8 h-[calc(100dvh-4rem)] md:h-[100dvh] flex flex-col">
        <div className="shrink-0 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold text-text-primary mb-2 flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-rose-500" /> Security Center
            </h1>
            <p className="text-text-secondary">Manage and acknowledge security alerts and blocked entities.</p>
          </div>
          <div className="flex items-center gap-3 w-full md:w-auto">
            <div className="relative flex-1 md:w-64">
              <Search className="w-4 h-4 text-text-secondary absolute left-3 top-1/2 -translate-y-1/2" />
              <input 
                type="text"
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-bg-secondary border border-border-subtle rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:border-accent-cyan"
              />
            </div>
            <button 
              onClick={fetchAlerts}
              className="p-2 border border-border-subtle bg-bg-tertiary rounded-lg hover:bg-bg-secondary transition-colors"
            >
              <RefreshCw className={`w-4 h-4 text-text-secondary ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 bg-bg-secondary border border-border-subtle rounded-xl flex flex-col overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-full text-text-secondary">Loading alerts...</div>
          ) : (
            <div className="flex-1 overflow-auto p-4">
              <DataTable 
                data={filteredAlerts}
                emptyMessage="No alerts found."
                columns={[
                  { header: "Time", cell: (r) => new Date(r.created_at).toLocaleString(), className: "text-text-secondary text-xs" },
                  { header: "Type", cell: (r) => <span className="font-semibold text-text-primary">{r.alert_type}</span> },
                  { header: "Severity", cell: (r) => <AlertBadge severity={r.severity.toLowerCase()} /> },
                  { header: "Source IP", accessorKey: "src_ip", className: "font-mono text-xs text-text-secondary" },
                  { header: "Description", cell: (r) => <span className="text-sm line-clamp-1" title={r.description}>{r.description}</span> },
                  { header: "Status", cell: (r) => (
                    r.acknowledged ? 
                      <span className="flex items-center gap-1 text-xs font-bold text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded-full w-fit"><CheckCircle2 className="w-3 h-3"/> Ack'd</span> : 
                      <span className="flex items-center gap-1 text-xs font-bold text-amber-500 bg-amber-500/10 px-2 py-1 rounded-full w-fit">Active</span>
                  )},
                  { header: "Actions", cell: (r) => (
                    !r.acknowledged ? (
                      <button 
                        onClick={() => handleAcknowledge(r.id)}
                        className="text-xs font-medium bg-accent-cyan/10 text-accent-cyan hover:bg-accent-cyan hover:text-bg-primary px-3 py-1.5 rounded-md transition-colors"
                      >
                        Acknowledge
                      </button>
                    ) : null
                  )}
                ]}
              />
            </div>
          )}
        </div>
      </div>
    </AuthGuard>
  );
}
