"use client";

import { BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface BarChartProps {
  data: any[];
  xKey: string;
  yKey: string;
  height?: number;
  layout?: 'horizontal' | 'vertical';
  colors?: string[];
  defaultColor?: string;
}

export function BarChart({ 
  data, 
  xKey, 
  yKey, 
  height = 300, 
  layout = 'horizontal',
  colors,
  defaultColor = '#38bdf8' 
}: BarChartProps) {
  
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
        <RechartsBarChart
          layout={layout}
          data={data}
          margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" horizontal={layout === 'horizontal'} vertical={layout === 'vertical'} />
          {layout === 'horizontal' ? (
            <>
              <XAxis dataKey={xKey} stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
            </>
          ) : (
            <>
              <XAxis type="number" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis dataKey={xKey} type="category" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} width={100} />
            </>
          )}
          <Tooltip 
            cursor={{ fill: 'rgba(255,255,255,0.05)' }} 
            contentStyle={{ backgroundColor: '#111827', borderColor: 'rgba(148,163,184,0.2)', color: '#f8fafc', borderRadius: '8px' }}
            itemStyle={{ color: '#38bdf8' }}
          />
          <Bar dataKey={yKey} radius={[4, 4, 4, 4]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={colors ? colors[index % colors.length] : defaultColor} />
            ))}
          </Bar>
        </RechartsBarChart>
      </ResponsiveContainer>
    </div>
  );
}
