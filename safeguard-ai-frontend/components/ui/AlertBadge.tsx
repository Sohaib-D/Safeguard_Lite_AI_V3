import { getSeverityColor, cn } from "../../lib/utils";

interface AlertBadgeProps {
  severity: string;
  className?: string;
}

export function AlertBadge({ severity, className }: AlertBadgeProps) {
  const colorClass = getSeverityColor(severity);
  
  return (
    <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide border", colorClass, className)}>
      {severity}
    </span>
  );
}
