"use client";

import { useState } from "react";
import { Sidebar } from "../../components/layout/Sidebar";
import { Topbar } from "../../components/layout/Topbar";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { Home, Shield, Activity, BarChart2, Menu, Search, Radio, Server, BookOpen, ShieldAlert } from "lucide-react";
import { cn } from "../../lib/utils";

const toolsTabs = [
  { name: "Active Scanner", href: "/app/active-scanner", icon: Search },
  { name: "Deep Scanner", href: "/app/deep-scanner", icon: Shield },
  { name: "Live Monitor", href: "/app/live-monitor", icon: Radio },
  { name: "Capture Control", href: "/app/capture-control", icon: Server },
  { name: "Security Center", href: "/app/security-center", icon: ShieldAlert },
  { name: "Beginner Guide", href: "/app/beginner-guide", icon: BookOpen },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  // The login page doesn't need the sidebar or topbar
  if (pathname === "/app" || pathname === "/app/") {
    return <main>{children}</main>;
  }

  const isToolPage = toolsTabs.some(t => pathname === t.href);

  return (
    <div className="flex h-[100dvh] overflow-hidden bg-bg-primary pb-[env(safe-area-inset-bottom)]">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex-1 flex flex-col min-w-0 relative overflow-hidden">
        <Topbar onMenuClick={() => setSidebarOpen(true)} />

        {/* Tools Tab Bar */}
        <nav className="shrink-0 border-b border-border-subtle bg-bg-secondary overflow-x-auto scrollbar-thin">
          <div className="flex items-center min-w-max px-2">
            {toolsTabs.map((tab) => {
              const isActive = pathname === tab.href;
              return (
                <Link
                  key={tab.href}
                  href={tab.href}
                  className={cn(
                    "flex items-center gap-2 px-4 py-3 text-xs font-medium border-b-2 transition-all whitespace-nowrap",
                    isActive
                      ? "border-accent-cyan text-accent-cyan bg-accent-cyan/5"
                      : "border-transparent text-text-secondary hover:text-text-primary hover:bg-bg-tertiary/50"
                  )}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  {tab.name}
                </Link>
              );
            })}
          </div>
        </nav>

        <main className="flex-1 overflow-y-auto overflow-x-hidden relative scrollbar-thin pb-16 md:pb-0">
          {children}
        </main>

        {/* Mobile Bottom Navigation */}
        <nav className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-bg-secondary/90 backdrop-blur-md border-t border-border-subtle pb-[env(safe-area-inset-bottom)]">
          <div className="flex items-center justify-around h-16 px-2">
            <Link href="/app/home" className={cn("flex flex-col items-center justify-center w-full h-full space-y-1", pathname === '/app/home' ? "text-accent-cyan" : "text-text-secondary")}>
              <Home className="w-5 h-5" />
              <span className="text-[10px]">Home</span>
            </Link>
            <Link href="/app/deep-scanner" className={cn("flex flex-col items-center justify-center w-full h-full space-y-1", pathname === '/app/deep-scanner' ? "text-accent-cyan" : "text-text-secondary")}>
              <Shield className="w-5 h-5" />
              <span className="text-[10px]">Scanner</span>
            </Link>
            <Link href="/app/live-predictions" className={cn("flex flex-col items-center justify-center w-full h-full space-y-1", pathname === '/app/live-predictions' ? "text-accent-cyan" : "text-text-secondary")}>
              <Activity className="w-5 h-5" />
              <span className="text-[10px]">Live</span>
            </Link>
            <Link href="/app/statistics" className={cn("flex flex-col items-center justify-center w-full h-full space-y-1", pathname === '/app/statistics' ? "text-accent-cyan" : "text-text-secondary")}>
              <BarChart2 className="w-5 h-5" />
              <span className="text-[10px]">Stats</span>
            </Link>
            <button onClick={() => setSidebarOpen(true)} className="flex flex-col items-center justify-center w-full h-full space-y-1 text-text-secondary">
              <Menu className="w-5 h-5" />
              <span className="text-[10px]">More</span>
            </button>
          </div>
        </nav>
      </div>
    </div>
  );
}
