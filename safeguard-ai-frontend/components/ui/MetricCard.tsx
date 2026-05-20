import { ReactNode } from "react";
import { cn } from "../../lib/utils";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  subtitle?: string;
  className?: string;
  valueClassName?: string;
}

export function MetricCard({ title, value, icon, subtitle, className, valueClassName }: MetricCardProps) {
  return (
    <div className={cn("bg-bg-secondary border border-border-subtle rounded-xl p-6 shadow-sm flex flex-col", className)}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-text-secondary">{title}</h3>
        {icon && <div className="text-accent-cyan opacity-80">{icon}</div>}
      </div>
      <div className="flex items-baseline gap-2">
        <div className={cn("text-3xl font-bold text-text-primary tracking-tight", valueClassName)}>
          {value}
        </div>
      </div>
      {subtitle && (
        <p className="mt-2 text-xs text-text-secondary opacity-80">{subtitle}</p>
      )}
    </div>
  );
}
