"use client";

import { Shield, Menu, User, Lock } from "lucide-react";
import { useAppStore } from "../../store/useAppStore";
import { cn } from "../../lib/utils";

interface TopbarProps {
  onMenuClick: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  const { authUser, authRole, authToken } = useAppStore();
  const isSignedIn = !!authToken;

  return (
    <header className="sticky top-0 z-40 w-full bg-bg-primary/80 backdrop-blur-md border-b border-border-subtle h-16 flex items-center justify-between px-4 lg:px-8">
      <div className="flex items-center gap-3">
        <button 
          onClick={onMenuClick}
          className="lg:hidden p-2 -ml-2 text-text-secondary hover:text-text-primary rounded-md"
        >
          <Menu className="w-6 h-6" />
        </button>
        <div className="flex items-center gap-2">
          <div className="bg-accent-cyan/10 p-1.5 rounded-lg border border-accent-cyan/20">
            <Shield className="w-5 h-5 text-accent-cyan" />
          </div>
          <div>
            <h1 className="font-bold text-text-primary leading-tight hidden sm:block">Safeguard-AI Lite</h1>
            <p className="text-[10px] text-text-secondary tracking-widest uppercase hidden sm:block">Security Intelligence</p>
          </div>
        </div>
      </div>

      <div className="flex items-center">
        {isSignedIn ? (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
            <User className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">{authUser} ({authRole})</span>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 ml-1 shadow-[0_0_8px_rgba(52,211,153,0.8)]"></span>
            <span className="hidden sm:inline">Signed In</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-500 text-xs font-medium">
            <Lock className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Not Signed In</span>
          </div>
        )}
      </div>
    </header>
  );
}
