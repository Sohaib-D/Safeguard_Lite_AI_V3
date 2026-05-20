import { cn } from "../../lib/utils";

export function LoadingSpinner({ className }: { className?: string }) {
  return (
    <div className={cn("flex justify-center items-center p-8", className)}>
      <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-accent-cyan"></div>
    </div>
  );
}
