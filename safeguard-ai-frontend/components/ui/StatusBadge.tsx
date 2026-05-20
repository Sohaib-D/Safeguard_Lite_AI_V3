import { getGradeColor, cn } from "../../lib/utils";

export function StatusBadge({ grade, className }: { grade: string, className?: string }) {
  const colorClass = getGradeColor(grade);
  
  return (
    <span className={cn("inline-flex items-center px-3 py-1 rounded-full text-sm font-bold bg-bg-tertiary/50 border border-border-subtle", colorClass, className)}>
      {grade}
    </span>
  );
}
