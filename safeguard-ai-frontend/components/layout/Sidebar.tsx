"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  Home, Upload, Activity, BarChart2, PieChart, Info, ShieldAlert,
  Shield, LogOut, X, ChevronLeft
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { logout } from "../../lib/auth";

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

const mainNav = [
  { name: "Home", href: "/app/home", icon: Home },
  { name: "Upload", href: "/app/upload", icon: Upload },
  { name: "Live Predictions", href: "/app/live-predictions", icon: Activity },
  { name: "Statistics", href: "/app/statistics", icon: BarChart2 },
  { name: "Analytics", href: "/app/analytics", icon: PieChart },
  { name: "Explanations", href: "/app/explanations", icon: Info },
  { name: "SOC Dashboard", href: "/app/soc-dashboard", icon: ShieldAlert },
  { name: "About", href: "/app/about", icon: Info },
];




export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const { deepScanHistory, totalVulnsFound, totalCriticalFound } = useAppStore();
  const deepScansCount = deepScanHistory.filter(h => h.type === 'deep').length;
  
  const NavItem = ({ item }: { item: any }) => {
    const isActive = pathname === item.href;
    return (
      <Link 
        href={item.href}
        title={isCollapsed ? item.name : undefined}
        onClick={() => { if (window.innerWidth < 1024) onClose(); }}
        className={cn(
          "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
          isActive 
            ? "bg-accent-cyan/10 text-accent-cyan font-medium" 
            : "text-text-secondary hover:bg-bg-tertiary hover:text-text-primary",
          isCollapsed && "justify-center px-0"
        )}
      >
        <item.icon className={cn("shrink-0", isCollapsed ? "w-5 h-5" : "w-4 h-4", isActive ? "text-accent-cyan" : "opacity-70")} />
        {!isCollapsed && <span className="truncate">{item.name}</span>}
      </Link>
    );
  };

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/60 z-40 lg:hidden backdrop-blur-sm"
          onClick={onClose}
        />
      )}

      {/* Sidebar Container */}
      <aside className={cn(
        "fixed top-0 left-0 z-50 h-[100dvh] bg-bg-secondary border-r border-border-subtle flex flex-col transition-all duration-300 lg:translate-x-0 lg:sticky lg:h-screen",
        isOpen ? "translate-x-0" : "-translate-x-full",
        isCollapsed ? "w-20" : "w-72"
      )}>
        <div className={cn("flex items-center p-4 border-b border-border-subtle", isCollapsed ? "justify-center" : "justify-between")}>
          {!isCollapsed && (
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-accent-cyan shrink-0" />
              <span className="font-bold text-text-primary truncate">Safeguard-AI</span>
            </div>
          )}
          {isCollapsed && <Shield className="w-6 h-6 text-accent-cyan shrink-0 hidden lg:block" />}
          <div className="flex items-center">
            <button onClick={() => setIsCollapsed(!isCollapsed)} className="hidden lg:flex p-1.5 text-text-secondary hover:text-text-primary rounded-lg hover:bg-bg-tertiary transition-colors">
              <ChevronLeft className={cn("w-5 h-5 transition-transform duration-300", isCollapsed && "rotate-180")} />
            </button>
            <button onClick={onClose} className="p-1 text-text-secondary hover:text-text-primary lg:hidden ml-auto">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className={cn("flex-1 overflow-y-auto py-4 space-y-6 scrollbar-thin", isCollapsed ? "px-2" : "px-3")}>
          <div>
            {!isCollapsed && <h4 className="px-3 mb-2 text-xs font-semibold text-text-secondary uppercase tracking-wider">Main</h4>}
            <div className="space-y-1">
              {mainNav.map(item => <NavItem key={item.name} item={item} />)}
            </div>
          </div>

        </div>


        <div className={cn("p-4 border-t border-border-subtle bg-bg-primary/30", isCollapsed && "px-2")}>
          {!isCollapsed && (
            <>
              <h4 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">Session Stats</h4>
              <div className="grid grid-cols-2 gap-2 mb-4">
                <div className="bg-bg-tertiary p-2 rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-cyan">{deepScansCount}</div>
                  <div className="text-[10px] text-text-secondary uppercase">Deep Scans</div>
                </div>
                <div className="bg-bg-tertiary p-2 rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-violet">0</div>
                  <div className="text-[10px] text-text-secondary uppercase">ML Predicts</div>
                </div>
                <div className="bg-bg-tertiary p-2 rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-amber">{totalVulnsFound}</div>
                  <div className="text-[10px] text-text-secondary uppercase">Vulns Found</div>
                </div>
                <div className="bg-bg-tertiary p-2 rounded-lg text-center">
                  <div className="text-lg font-bold text-accent-rose">{totalCriticalFound}</div>
                  <div className="text-[10px] text-text-secondary uppercase">Critical</div>
                </div>
              </div>
            </>
          )}
          
          <button 
            onClick={logout}
            title={isCollapsed ? "Logout" : undefined}
            className={cn(
              "flex items-center text-sm text-text-secondary hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors",
              isCollapsed ? "justify-center py-3 px-0 w-full" : "justify-center gap-2 py-2 w-full"
            )}
          >
            <LogOut className={cn(isCollapsed ? "w-5 h-5" : "w-4 h-4")} />
            {!isCollapsed && <span>Logout</span>}
          </button>
        </div>
      </aside>
    </>
  );
}
