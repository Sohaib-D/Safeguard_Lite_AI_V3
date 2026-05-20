"use client";

import { useState, useEffect } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { DataTable } from "../../../components/ui/DataTable";
import { PieChart } from "../../../components/ui/PieChart";
import { AlertBadge } from "../../../components/ui/AlertBadge";
import { modelAPI } from "../../../lib/api";
import { useAppStore } from "../../../store/useAppStore";
import { Activity, Play, Zap, AlertTriangle } from "lucide-react";
import { cn } from "../../../lib/utils";

// Mock profiles for the select dropdown (since we don't have the exact list from backend)
const ATTACK_PROFILES = [
  "Normal Traffic", "DoS / DDoS", "Port Scan", "Brute Force", "Web Attack"
];

export default function LivePredictionsPage() {
  const [selectedProfile, setSelectedProfile] = useState(ATTACK_PROFILES[0]);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationInterval, setSimulationInterval] = useState<ReturnType<typeof setInterval> | null>(null);
  const { latestPredictionResult, setLatestPrediction, liveHistory, appendLiveEvent, modelInfoCache, setModelInfo } = useAppStore();

  useEffect(() => {
    if (!modelInfoCache) {
      modelAPI.getModelInfo().then(setModelInfo).catch(err => console.error("Model info failed", err));
    }
  }, [modelInfoCache, setModelInfo]);

  // Helper: uniform random in [lo, hi]
  const rand = (lo: number, hi: number) => +(lo + Math.random() * (hi - lo)).toFixed(4);
  const pick = <T,>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)];

  // Feature profiles matching the ACTUAL model training data (f0-f9 + service)
  // Values are mean ± ~1 std from per-class distributions
  const buildFeatures = (profileName: string): Record<string, any> => {
    const schema = modelInfoCache?.raw_input_schema || {};
    const numericColumns: string[] = schema.numeric_columns || Array.from({ length: 10 }, (_, i) => `f${i}`);
    const categoricalColumns: string[] = schema.categorical_columns || ["service"];
    const f: Record<string, any> = {};

    //               f0          f1          f2          f3          f4          f5          f6          f7          f8          f9
    let ranges: number[][] = [];
    let svcChoices: string[] = ["http", "dns", "ssh"];

    if (profileName === "Normal Traffic") {
      ranges = [[0.4,1.8],[-1.8,-0.3],[-1.8,-0.4],[0.1,1.5],[-0.8,1.0],[0.3,1.7],[0.2,1.6],[-1.7,-0.3],[-0.6,0.7],[0.4,1.8]];
      svcChoices = ["ssh", "ssh", "http", "dns"];
    } else if (profileName.includes("DoS") || profileName.includes("DDoS")) {
      ranges = [[-1.6,-0.2],[0.4,2.0],[-3.5,-2.0],[0.3,1.8],[-1.0,0.8],[-1.6,-0.2],[-1.7,-0.3],[-1.9,-0.5],[-0.6,0.7],[-1.4,0.0]];
      svcChoices = ["dns", "dns", "http", "ssh"];
    } else if (profileName.includes("Brute")) {
      ranges = [[0.3,1.7],[0.2,1.7],[-1.7,-0.3],[-1.7,-0.3],[-1.0,0.7],[0.1,1.4],[0.5,1.9],[-1.2,0.3],[-0.7,0.6],[0.2,1.6]];
      svcChoices = ["dns", "http", "ssh"];
    } else if (profileName.includes("Port Scan")) {
      ranges = [[0.2,1.6],[-1.7,-0.3],[0.9,2.3],[-1.7,-0.3],[-0.7,0.8],[0.2,1.6],[0.3,1.7],[-1.8,-0.4],[-0.9,0.4],[-1.7,-0.3]];
      svcChoices = ["http", "http", "dns", "ssh"];
    } else {
      // Web Attack / fallback
      ranges = [[0.0,1.0],[0.0,1.0],[-1.5,0.5],[0.0,1.0],[-0.5,0.5],[0.0,1.0],[0.0,1.0],[-1.0,0.0],[-0.5,0.5],[0.0,1.0]];
      svcChoices = ["http", "http", "http", "ssh"];
    }

    numericColumns.forEach((col, i) => {
      const r = ranges[i] || [-1, 1];
      f[col] = rand(r[0], r[1]);
    });
    categoricalColumns.forEach(col => { f[col] = pick(svcChoices); });

    return f;
  };

  const runPrediction = async (profileName: string) => {
    try {
      const features = buildFeatures(profileName);

      const res = await modelAPI.predict(features);
      setLatestPrediction(res);
      
      if (res.prediction !== "Normal") {
        // Map attack type to severity tier: DDoS = critical, BruteForce/PortScan = high
        const severityMap: Record<string, string> = {
          "DDoS": "critical",
          "BruteForce": "high",
          "PortScan": "high",
        };
        const severity = severityMap[res.prediction] || "high";
        appendLiveEvent({
          timestamp: new Date().toISOString(),
          type: res.prediction,
          details: `Model classified generated ${profileName} feature vector as ${res.prediction}`,
          severity,
        });
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleManualRun = () => runPrediction(selectedProfile);

  const toggleSimulation = () => {
    if (isSimulating) {
      if (simulationInterval) clearInterval(simulationInterval);
      setSimulationInterval(null);
      setIsSimulating(false);
    } else {
      setIsSimulating(true);
      const int = setInterval(() => {
        const randomProfile = ATTACK_PROFILES[Math.floor(Math.random() * ATTACK_PROFILES.length)];
        runPrediction(randomProfile);
      }, 3000);
      setSimulationInterval(int);
    }
  };

  useEffect(() => {
    return () => {
      if (simulationInterval) clearInterval(simulationInterval);
    };
  }, [simulationInterval]);

  // Derive pie chart data from liveHistory
  const pieData = liveHistory.reduce((acc: any[], event) => {
    const existing = acc.find(a => a.name === event.type);
    if (existing) existing.value += 1;
    else acc.push({ name: event.type, value: 1 });
    return acc;
  }, []);

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold text-text-primary mb-2">Live Predictions</h1>
            <p className="text-text-secondary">Simulate and monitor live ML classification of network traffic.</p>
          </div>
          
          <div className="flex items-center gap-3 w-full md:w-auto">
            <select 
              value={selectedProfile}
              onChange={(e) => setSelectedProfile(e.target.value)}
              className="bg-bg-secondary border border-border-subtle text-text-primary rounded-lg px-4 py-2.5 focus:outline-none focus:border-accent-cyan flex-1 md:w-48"
            >
              {ATTACK_PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            
            <button 
              onClick={handleManualRun}
              className="p-2.5 bg-bg-tertiary hover:bg-bg-secondary border border-border-subtle rounded-lg text-text-primary transition-colors"
              title="Run Single Prediction"
            >
              <Zap className="w-5 h-5 text-accent-amber" />
            </button>
            
            <button 
              onClick={toggleSimulation}
              className={cn(
                "px-4 py-2.5 rounded-lg font-medium border flex items-center gap-2 transition-all flex-1 justify-center",
                isSimulating 
                  ? "bg-rose-500/20 text-rose-500 border-rose-500/50 hover:bg-rose-500/30" 
                  : "bg-emerald-500/20 text-emerald-500 border-emerald-500/50 hover:bg-emerald-500/30"
              )}
            >
              <Activity className={cn("w-4 h-4", isSimulating && "animate-pulse")} />
              {isSimulating ? "Stop Feed" : "Start Live Feed"}
            </button>
          </div>
        </div>

        {/* Latest Prediction Card */}
        {latestPredictionResult && (
          <div className={cn(
            "p-6 rounded-2xl border transition-colors",
            latestPredictionResult.prediction === "Normal" 
              ? "bg-emerald-500/5 border-emerald-500/20" 
              : "bg-rose-500/5 border-rose-500/20"
          )}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Latest Classification</h3>
              <span className="text-xs text-text-secondary">{new Date().toLocaleTimeString()}</span>
            </div>
            <div className="flex items-end gap-4">
              <div className={cn(
                "text-4xl font-bold tracking-tight",
                latestPredictionResult.prediction === "Normal" ? "text-emerald-400" : "text-rose-500"
              )}>
                {latestPredictionResult.prediction}
              </div>
              <div className="mb-1 text-sm text-text-secondary">
                Confidence: <span className="font-bold text-text-primary">{((latestPredictionResult.probabilities[latestPredictionResult.prediction] || 0) * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <h2 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-accent-rose" /> Recent Alerts
            </h2>
            <DataTable 
              data={liveHistory.slice(-10).reverse()}
              emptyMessage="No attacks detected yet."
              columns={[
                { header: "Time", cell: (r) => new Date(r.timestamp).toLocaleTimeString(), className: "text-text-secondary w-24" },
                { header: "Type", cell: (r) => <span className="text-rose-500 font-medium">{r.type}</span> },
                { header: "Severity", cell: (r) => <AlertBadge severity={r.severity} /> },
                { header: "Details", accessorKey: "details" },
              ]}
            />
          </div>
          
          <div>
            <h2 className="text-lg font-bold text-text-primary mb-4">Attack Distribution</h2>
            <div className="bg-bg-secondary border border-border-subtle rounded-xl p-4">
              {pieData.length > 0 ? (
                <PieChart data={pieData} height={250} />
              ) : (
                <div className="h-[250px] flex items-center justify-center text-text-secondary">
                  No data available yet
                </div>
              )}
            </div>
          </div>
        </div>

      </div>
    </AuthGuard>
  );
}
