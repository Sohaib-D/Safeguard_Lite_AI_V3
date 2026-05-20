"use client";

import { AuthGuard } from "../../../components/layout/AuthGuard";
import { BookOpen, Shield, Zap, Search, Activity } from "lucide-react";

export default function BeginnerGuidePage() {
  return (
    <AuthGuard requireAuth={false}>
      <div className="p-4 md:p-8 space-y-8 max-w-5xl mx-auto">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-text-primary mb-4 flex items-center justify-center gap-3">
            <BookOpen className="w-8 h-8 text-accent-cyan" /> Beginner's Security Guide
          </h1>
          <p className="text-text-secondary max-w-2xl mx-auto">
            Welcome to Safeguard-AI Lite! This guide will help you understand basic cybersecurity concepts and how to use our platform effectively.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6 hover:border-accent-cyan/50 transition-colors">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-emerald-500/10 rounded-lg">
                <Shield className="w-6 h-6 text-emerald-400" />
              </div>
              <h2 className="text-xl font-bold text-text-primary">What is Intrusion Detection?</h2>
            </div>
            <p className="text-text-secondary leading-relaxed mb-4">
              An Intrusion Detection System (IDS) acts like a security camera for your network. It monitors incoming and outgoing traffic to identify suspicious activity or known threats.
            </p>
            <div className="bg-bg-primary p-4 rounded-lg border border-border-subtle">
              <span className="text-sm font-semibold text-text-primary block mb-2">How we help:</span>
              <span className="text-sm text-text-secondary">Our ML model analyzes traffic in real-time (via the SOC Dashboard) or in batch (via Upload) to automatically classify attacks like DDoS or Brute Force.</span>
            </div>
          </div>

          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6 hover:border-accent-violet/50 transition-colors">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-accent-violet/10 rounded-lg">
                <Search className="w-6 h-6 text-accent-violet" />
              </div>
              <h2 className="text-xl font-bold text-text-primary">What is Active Reconnaissance?</h2>
            </div>
            <p className="text-text-secondary leading-relaxed mb-4">
              Reconnaissance is the process of gathering information about a target (like a server or website). Think of it as checking if the doors and windows of a house are locked.
            </p>
            <div className="bg-bg-primary p-4 rounded-lg border border-border-subtle">
              <span className="text-sm font-semibold text-text-primary block mb-2">How we help:</span>
              <span className="text-sm text-text-secondary">The Active Scanner checks for open ports and basic info. The Deep Scanner goes further, giving a full security grade and finding critical vulnerabilities.</span>
            </div>
          </div>

          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6 hover:border-accent-amber/50 transition-colors">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-accent-amber/10 rounded-lg">
                <Zap className="w-6 h-6 text-accent-amber" />
              </div>
              <h2 className="text-xl font-bold text-text-primary">Common Attack Types</h2>
            </div>
            <ul className="space-y-4">
              <li>
                <span className="text-text-primary font-semibold block">DoS / DDoS</span>
                <span className="text-text-secondary text-sm">Flooding a server with traffic so it crashes or becomes unavailable to legitimate users.</span>
              </li>
              <li>
                <span className="text-text-primary font-semibold block">Brute Force</span>
                <span className="text-text-secondary text-sm">Continuously guessing passwords until the correct one is found.</span>
              </li>
              <li>
                <span className="text-text-primary font-semibold block">Port Scan</span>
                <span className="text-text-secondary text-sm">Probing a server to see which doors (ports) are open and what software is running behind them.</span>
              </li>
            </ul>
          </div>

          <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6 hover:border-rose-500/50 transition-colors">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-rose-500/10 rounded-lg">
                <Activity className="w-6 h-6 text-rose-500" />
              </div>
              <h2 className="text-xl font-bold text-text-primary">What is a SOC?</h2>
            </div>
            <p className="text-text-secondary leading-relaxed mb-4">
              A Security Operations Center (SOC) is a centralized team or dashboard where security analysts monitor, detect, and respond to incidents in real-time.
            </p>
            <div className="bg-bg-primary p-4 rounded-lg border border-border-subtle">
              <span className="text-sm font-semibold text-text-primary block mb-2">How we help:</span>
              <span className="text-sm text-text-secondary">Our SOC Dashboard streams live alerts. Use the SOC Assistant (AI Chatbot) to ask questions about alerts or get advice on how to respond.</span>
            </div>
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}
