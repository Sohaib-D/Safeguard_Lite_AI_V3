"use client";

import { AuthGuard } from "../../../components/layout/AuthGuard";
import { MetricCard } from "../../../components/ui/MetricCard";
import { BarChart } from "../../../components/ui/BarChart";
import { LineChart } from "../../../components/ui/LineChart";
import { DataTable } from "../../../components/ui/DataTable";
import { useAppStore } from "../../../store/useAppStore";
import { PieChart, TrendingUp, AlertOctagon } from "lucide-react";

export default function AnalyticsPage() {
  const { liveHistory } = useAppStore();

  const attackTypesMap: Record<string, number> = {};
  const dailyTrendMap: Record<string, number> = {};

  liveHistory.forEach(event => {
    // Attack Types
    attackTypesMap[event.type] = (attackTypesMap[event.type] || 0) + 1;
    
    // Daily Trend (Group by hour)
    const date = new Date(event.timestamp);
    const hour = date.getHours().toString().padStart(2, '0') + ':00';
    dailyTrendMap[hour] = (dailyTrendMap[hour] || 0) + 1;
  });

  const attackTypes = Object.entries(attackTypesMap)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  // If no data, show empty array. We can sort by time.
  const dailyTrend = Object.entries(dailyTrendMap)
    .map(([time, events]) => ({ time, events }))
    .sort((a, b) => a.time.localeCompare(b.time));

  // Ensure we have something to render if empty
  const displayAttackTypes = attackTypes.length > 0 ? attackTypes : [{ type: "No Data", count: 0 }];
  const displayDailyTrend = dailyTrend.length > 0 ? dailyTrend : [{ time: "00:00", events: 0 }];

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2">Threat Analytics</h1>
          <p className="text-text-secondary">Deep dive into attack vectors, trends, and historical metrics.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard title="Total Monitored Traffic" value="1.2 TB" icon={<PieChart className="w-5 h-5"/>} />
          <MetricCard title="Threats Prevented" value="2,845" icon={<AlertOctagon className="w-5 h-5"/>} valueClassName="text-emerald-400" />
          <MetricCard title="Active Threats" value={liveHistory.length} icon={<TrendingUp className="w-5 h-5"/>} valueClassName="text-rose-500" />
          <MetricCard title="High Risk Sources" value="12" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-bg-secondary p-6 border border-border-subtle rounded-xl">
            <h2 className="text-lg font-bold text-text-primary mb-6">Attack Type Breakdown</h2>
            <BarChart 
              data={displayAttackTypes} 
              xKey="type" 
              yKey="count" 
              layout="vertical"
              colors={['#fb7185', '#fbbf24', '#38bdf8', '#a78bfa']} 
            />
          </div>

          <div className="bg-bg-secondary p-6 border border-border-subtle rounded-xl">
            <h2 className="text-lg font-bold text-text-primary mb-6">Daily Event Trend</h2>
            <LineChart 
              data={displayDailyTrend} 
              xKey="time" 
              yKey="events" 
              color="#38bdf8"
            />
          </div>
        </div>

        <div>
          <h2 className="text-lg font-bold text-text-primary mb-4">Recent Event Feed</h2>
          <DataTable 
            data={liveHistory.slice(-5).reverse()}
            emptyMessage="No events to display."
            columns={[
              { header: "Timestamp", accessorKey: "timestamp", className: "w-48 text-text-secondary" },
              { header: "Event Type", accessorKey: "type", className: "font-medium text-accent-cyan" },
              { header: "Severity", accessorKey: "severity", className: "uppercase text-xs" },
              { header: "Details", accessorKey: "details" },
            ]}
          />
        </div>
      </div>
    </AuthGuard>
  );
}
