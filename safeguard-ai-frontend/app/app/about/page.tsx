"use client";

import { AuthGuard } from "../../../components/layout/AuthGuard";
import { Info, Shield, Server, Code2 } from "lucide-react";

export default function AboutPage() {
  return (
    <AuthGuard requireAuth={false}>
      <div className="p-4 md:p-8 space-y-8 max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center p-4 bg-accent-cyan/10 rounded-2xl border border-accent-cyan/20 mb-6">
            <Shield className="w-12 h-12 text-accent-cyan" />
          </div>
          <h1 className="text-3xl font-bold text-text-primary mb-2">Safeguard-AI Lite</h1>
          <p className="text-text-secondary">Version 2.0.0 (Next.js Edition)</p>
        </div>

        <div className="bg-bg-secondary border border-border-subtle rounded-xl overflow-hidden">
          <div className="p-6 border-b border-border-subtle">
            <h2 className="text-lg font-bold text-text-primary flex items-center gap-2">
              <Info className="w-5 h-5 text-accent-cyan" /> Platform Overview
            </h2>
          </div>
          <div className="p-6">
            <p className="text-text-secondary leading-relaxed">
              Safeguard-AI Lite is an integrated, ML-powered cybersecurity platform designed for proactive defense and real-time monitoring. 
              It combines robust network intrusion detection with active reconnaissance capabilities, providing a unified pane of glass for security analysts.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
            <h3 className="text-md font-bold text-text-primary flex items-center gap-2 mb-4">
              <Code2 className="w-5 h-5 text-emerald-400" /> Technology Stack
            </h3>
            <ul className="space-y-3 text-sm text-text-secondary">
              <li className="flex justify-between"><span>Frontend</span> <span className="font-medium text-text-primary">Next.js 14, Tailwind CSS, Zustand</span></li>
              <li className="flex justify-between"><span>Backend API</span> <span className="font-medium text-text-primary">FastAPI (Python)</span></li>
              <li className="flex justify-between"><span>Machine Learning</span> <span className="font-medium text-text-primary">Scikit-Learn, Pandas</span></li>
              <li className="flex justify-between"><span>Database</span> <span className="font-medium text-text-primary">PostgreSQL (Supabase)</span></li>
              <li className="flex justify-between"><span>Real-time</span> <span className="font-medium text-text-primary">WebSockets</span></li>
            </ul>
          </div>

          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
            <h3 className="text-md font-bold text-text-primary flex items-center gap-2 mb-4">
              <Server className="w-5 h-5 text-accent-violet" /> Architecture
            </h3>
            <p className="text-sm text-text-secondary leading-relaxed mb-4">
              The platform utilizes a decoupled architecture. The Next.js frontend acts as a Progressive Web App (PWA) client that communicates with the centralized FastAPI backend via REST APIs and WebSockets.
            </p>
            <p className="text-sm text-text-secondary leading-relaxed">
              Machine Learning inference and heavy network scanning logic are securely processed server-side to maintain client performance and ensure integrity.
            </p>
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}
