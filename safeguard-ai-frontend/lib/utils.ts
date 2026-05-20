import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string) {
  if (!dateString) return "N/A";
  try {
    const d = new Date(dateString);
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(d);
  } catch (e) {
    return dateString;
  }
}

export function getSeverityColor(severity: string) {
  switch (severity?.toLowerCase()) {
    case "critical": return "text-rose-500 bg-rose-500/10 border-rose-500/20";
    case "high": return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    case "medium": return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    case "low": return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
    default: return "text-slate-400 bg-slate-500/10 border-slate-500/20";
  }
}

export function getGradeColor(grade: string) {
  if (!grade) return "text-slate-400";
  if (grade.startsWith("A")) return "text-emerald-400";
  if (grade.startsWith("B")) return "text-cyan-400";
  if (grade.startsWith("C")) return "text-amber-400";
  if (grade.startsWith("D")) return "text-orange-500";
  if (grade.startsWith("F")) return "text-rose-500";
  return "text-slate-400";
}
