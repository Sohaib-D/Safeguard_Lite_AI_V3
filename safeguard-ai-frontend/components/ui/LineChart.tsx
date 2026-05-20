"use client";

import { LineChart as RechartsLineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface LineChartProps {
  data: any[];
  xKey: string;
  yKey: string;
  height?: number;
  color?: string;
}

export function LineChart({ data, xKey, yKey, height = 300, color = "#38bdf8" }: LineChartProps) {
  if (!data || data.length === 0) {
    return (
      <div style={{ height }} className="flex items-center justify-center text-text-secondary bg-bg-secondary/50 rounded-xl border border-border-subtle">
        No chart data available.
      </div>
    );
  }

  return (
    <div style={{ height, width: '100%' }}>
      <ResponsiveContainer width="100%" height="100%">
        <RechartsLineChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" vertical={false} />
          <XAxis dataKey={xKey} stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
          <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
          <Tooltip 
            contentStyle={{ backgroundColor: '#111827', borderColor: 'rgba(148,163,184,0.2)', color: '#f8fafc', borderRadius: '8px' }}
            itemStyle={{ color }}
          />
          <Line type="monotone" dataKey={yKey} stroke={color} strokeWidth={3} dot={{ r: 4, fill: color, strokeWidth: 0 }} activeDot={{ r: 6 }} />
        </RechartsLineChart>
      </ResponsiveContainer>
    </div>
  );
}
