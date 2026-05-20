"use client";

import { useEffect, useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { MetricCard } from "../../../components/ui/MetricCard";
import { DataTable } from "../../../components/ui/DataTable";
import { useAppStore } from "../../../store/useAppStore";
import { modelAPI } from "../../../lib/api";
import { Activity, ShieldCheck, Database, Zap, CheckCircle2, XCircle } from "lucide-react";
import axios from "axios";
import { API_BASE } from "../../../lib/api";

export default function HomePage() {
  const { authUser, modelInfoCache, setModelInfo, deepScanHistory } = useAppStore();
  const [isBackendUp, setIsBackendUp] = useState<boolean | null>(null);
  const [modelLoading, setModelLoading] = useState(false);

  useEffect(() => {
    // Ping backend health
    axios.get(`${API_BASE}/health`, { timeout: 5000 })
      .then(() => setIsBackendUp(true))
      .catch(() => setIsBackendUp(false));

    // Fetch model info if not cached
    if (!modelInfoCache) {
      setModelLoading(true);
      modelAPI.getModelInfo()
        .then(info => setModelInfo(info))
        .catch(err => console.error("Failed to load model info", err))
        .finally(() => setModelLoading(false));
    }
  }, [modelInfoCache, setModelInfo]);

  const getStartedSteps = [
    { step: 1, action: "Network Analysis", description: "Use the Upload tab to submit PCAP/CSV network logs for ML intrusion detection." },
    { step: 2, action: "Active Recon", description: "Go to Active Scanner for non-intrusive port scanning and OS fingerprinting." },
    { step: 3, action: "Deep Security", description: "Run a Deep Security Scan for comprehensive vulnerability assessment and posture grading." },
    { step: 4, action: "SOC Dashboard", description: "Monitor simulated or real-time traffic alerts in the SOC Dashboard." },
  ];

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        
        {/* Hero Section */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-bg-tertiary to-bg-secondary border border-border-subtle p-8 md:p-12">
          <div className="absolute top-0 right-0 -mt-20 -mr-20 w-80 h-80 bg-accent-cyan/10 blur-[100px] rounded-full" />
          <div className="relative z-10 max-w-3xl">
            <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-4">
              Welcome back, <span className="text-accent-cyan">{authUser}</span>
            </h1>
            <p className="text-text-secondary text-lg mb-8 leading-relaxed">
              Safeguard-AI Lite is your unified platform for network intrusion detection, active reconnaissance, and real-time security monitoring powered by advanced machine learning.
            </p>
            
            <div className="flex items-center gap-3 px-4 py-2 bg-bg-primary/50 backdrop-blur-sm rounded-lg border border-border-subtle inline-flex">
              <span className="text-sm font-medium text-text-secondary">Backend Status:</span>
              {isBackendUp === null ? (
                <span className="flex items-center gap-2 text-text-secondary text-sm"><div className="w-2 h-2 rounded-full bg-slate-400 animate-pulse" /> Checking...</span>
              ) : isBackendUp ? (
                <span className="flex items-center gap-2 text-emerald-400 text-sm font-bold"><CheckCircle2 className="w-4 h-4" /> ONLINE</span>
              ) : (
                <span className="flex items-center gap-2 text-rose-500 text-sm font-bold"><XCircle className="w-4 h-4" /> OFFLINE</span>
              )}
            </div>
          </div>
        </div>

        {/* System Overview Metrics */}
        <div>
          <h2 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-accent-cyan" /> System Overview
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard 
              title="Active Model" 
              value="Random Forest" 
              icon={<Database className="w-5 h-5" />} 
              subtitle={modelLoading ? "Loading..." : `v${modelInfoCache?.version || "Unknown"}`} 
            />
            <MetricCard 
              title="Attack Classes" 
              value={modelInfoCache?.label_classes?.length || 0} 
              icon={<ShieldCheck className="w-5 h-5" />} 
              subtitle="Supported threat types" 
            />
            <MetricCard 
              title="Input Features" 
              value={modelInfoCache?.feature_count || 0} 
              icon={<Zap className="w-5 h-5" />} 
              subtitle="Network attributes analyzed" 
            />
            <MetricCard 
              title="Session Scans" 
              value={deepScanHistory.length} 
              icon={<Activity className="w-5 h-5" />} 
              subtitle="Deep scans executed this session" 
            />
          </div>
        </div>

        {/* Getting Started */}
        <div>
          <h2 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
            <Zap className="w-5 h-5 text-accent-amber" /> Getting Started Guide
          </h2>
          <DataTable 
            data={getStartedSteps}
            columns={[
              { header: "Step", accessorKey: "step", className: "w-16 text-center font-bold text-accent-cyan" },
              { header: "Action", accessorKey: "action", className: "w-48 font-semibold" },
              { header: "Description", accessorKey: "description" },
            ]}
          />
        </div>

        {/* Model Details */}
        {modelInfoCache && (
          <div>
            <h2 className="text-lg font-bold text-text-primary mb-4">Detection Capabilities</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">Supported Attack Classes</h3>
                <div className="flex flex-wrap gap-2">
                  {modelInfoCache?.label_classes?.map((cls, i) => (
                    <span key={i} className="px-3 py-1 bg-bg-tertiary border border-border-subtle rounded-lg text-xs text-text-primary">
                      {cls}
                    </span>
                  ))}
                </div>
              </div>
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-4">Input Schema</h3>
                <p className="text-2xl font-mono text-accent-cyan bg-bg-primary px-4 py-3 rounded-lg border border-border-subtle inline-block">
                  {modelInfoCache.feature_count} Features
                </p>
                <p className="mt-4 text-sm text-text-secondary">
                  The model dynamically maps your CSV/PCAP input into the required {modelInfoCache.feature_count} features ({modelInfoCache.raw_input_schema?.numeric_columns?.length || 10} numeric, {modelInfoCache.raw_input_schema?.categorical_columns?.length || 1} categorical) for evaluation.
                </p>
              </div>
            </div>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
