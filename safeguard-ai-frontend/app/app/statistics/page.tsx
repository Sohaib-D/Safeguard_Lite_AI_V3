"use client";

import { useEffect, useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { MetricCard } from "../../../components/ui/MetricCard";
import { PieChart } from "../../../components/ui/PieChart";
import { modelAPI } from "../../../lib/api";
import { useScanHistory } from "../../../hooks/useScanHistory";
import { Database, Shield, Zap, Activity } from "lucide-react";

export default function StatisticsPage() {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const { totalScans, totalCriticalFound, totalVulnsFound } = useScanHistory();

  useEffect(() => {
    modelAPI.getStats()
      .then(res => setStats(res))
      .catch(err => console.error("Stats failed", err))
      .finally(() => setLoading(false));
  }, []);

  const attackPieData = Object.entries(stats?.predictions_by_label || {})
    .map(([name, value]) => ({ name, value: Number(value) }))
    .filter(item => item.value > 0);

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2">Platform Statistics</h1>
          <p className="text-text-secondary">Overview of system health, active protections, and ML metrics.</p>
        </div>

        <section>
          <h2 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
            <Database className="w-5 h-5 text-accent-cyan" /> ML Model Performance
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard title="Total Predictions" value={stats?.total_predictions || 0} icon={<Activity className="w-5 h-5"/>} />
            <MetricCard title="Avg Confidence" value={`${Math.round((stats?.avg_confidence || 0) * 100)}%`} icon={<Zap className="w-5 h-5"/>} />
            <MetricCard title="CSV Rows Scored" value={stats?.total_uploads || 0} />
            <MetricCard title="Critical Alerts" value={stats?.critical_threats || 0} valueClassName="text-rose-500" />
          </div>
        </section>

        <section>
          <h2 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-accent-violet" /> Reconnaissance Metrics
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard title="Deep Scans Executed" value={totalScans} />
            <MetricCard title="Total Vulnerabilities" value={totalVulnsFound} valueClassName="text-accent-amber" />
            <MetricCard title="Critical Risks" value={totalCriticalFound} valueClassName="text-rose-500" />
            <MetricCard title="Backend Scored Rows" value={stats?.total_scans || 0} />
          </div>
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <section className="bg-bg-secondary p-6 border border-border-subtle rounded-xl">
            <h2 className="text-lg font-bold text-text-primary mb-6">Prediction Distribution</h2>
            {attackPieData.length > 0 ? (
              <PieChart data={attackPieData} height={300} />
            ) : (
              <div className="h-[300px] flex items-center justify-center text-text-secondary">
                No prediction records found yet.
              </div>
            )}
          </section>
          <section className="bg-bg-secondary p-6 border border-border-subtle rounded-xl">
            <h2 className="text-lg font-bold text-text-primary mb-4">Data Integrity Notes</h2>
            <ul className="space-y-3 text-sm text-text-secondary">
              <li>Metrics are loaded from the backend database, not static demo values.</li>
              <li>Accuracy and false-positive rates are not shown unless measured by an evaluation dataset.</li>
              <li>Latest prediction: {stats?.latest_prediction_at ? new Date(stats.latest_prediction_at).toLocaleString() : "No backend record yet"}</li>
            </ul>
          </section>
        </div>

      </div>
    </AuthGuard>
  );
}
