"use client";

import { useState, useRef, useEffect } from "react";
import { useAppStore } from "../../store/useAppStore";
import { chatAPI } from "../../lib/api";
import { Shield, User, Send, X, MessageSquare } from "lucide-react";
import { cn } from "../../lib/utils";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export function FloatingAssistant() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: "assistant", content: "Hello! I'm your **Cyber Expert** assistant. I specialize in threat analysis, network security, and incident response. How can I help you today?" }
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const { latestPredictionResult, deepScanResult } = useAppStore();

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isOpen]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    const userMsg = input.trim();
    setInput("");
    setMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setIsLoading(true);
    try {
      const context = {
        latest_prediction: latestPredictionResult?.prediction ?? "None",
        latest_scan_grade: deepScanResult?.risk_grade ?? "None",
        latest_scan_score: deepScanResult?.overall_risk_score ?? "None"
      };
      const res = await chatAPI.chat(userMsg, context, messages.map(m => ({ role: m.role, content: m.content })));
      setMessages(prev => [...prev, { role: "assistant", content: res.reply || res.response || "No response received." }]);
    } catch {
      setMessages(prev => [...prev, { role: "assistant", content: "⚠️ Error communicating with AI. Please check the backend connection." }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  return (
    <>
      {/* Floating Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary rounded-full shadow-lg shadow-accent-cyan/30 transition-all hover:scale-105 font-semibold text-sm"
      >
        <Shield className="w-5 h-5" />
        {!isOpen && <span>Cyber Expert</span>}
        {isOpen && <X className="w-5 h-5" />}
      </button>

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed bottom-24 right-6 z-50 w-[390px] max-w-[calc(100vw-3rem)] h-[560px] max-h-[calc(100vh-8rem)] bg-bg-secondary border border-border-subtle rounded-2xl shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-bottom-5 fade-in duration-200">
          {/* Header */}
          <div className="p-4 border-b border-border-subtle bg-bg-primary shrink-0 flex items-center gap-3">
            <div className="bg-accent-cyan/10 p-2 rounded-lg border border-accent-cyan/20">
              <Shield className="w-5 h-5 text-accent-cyan" />
            </div>
            <div>
              <p className="font-bold text-text-primary text-sm">Cyber Expert</p>
              <p className="text-[10px] text-text-secondary uppercase tracking-wider">Safeguard-AI Assistant</p>
            </div>
            <button onClick={() => setIsOpen(false)} className="ml-auto text-text-secondary hover:text-text-primary">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-bg-primary/30" ref={scrollRef}>
            {messages.map((msg, i) => (
              <div key={i} className={cn("flex gap-3", msg.role === "user" ? "flex-row-reverse" : "flex-row")}>
                <div className={cn(
                  "shrink-0 w-8 h-8 rounded-full flex items-center justify-center border",
                  msg.role === "user"
                    ? "bg-bg-tertiary border-border-subtle"
                    : "bg-accent-cyan/10 border-accent-cyan/30"
                )}>
                  {msg.role === "user" ? <User className="w-4 h-4 text-text-primary" /> : <Shield className="w-4 h-4 text-accent-cyan" />}
                </div>
                <div className={cn(
                  "px-4 py-2.5 rounded-2xl text-[13px] shadow-sm max-w-[80%] leading-relaxed",
                  msg.role === "user"
                    ? "bg-accent-cyan text-bg-primary rounded-tr-sm"
                    : "bg-bg-secondary border border-border-subtle text-text-primary rounded-tl-sm whitespace-pre-wrap"
                )}>
                  {msg.content}
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex gap-3">
                <div className="shrink-0 w-8 h-8 rounded-full bg-accent-cyan/10 border border-accent-cyan/30 flex items-center justify-center">
                  <Shield className="w-4 h-4 text-accent-cyan" />
                </div>
                <div className="px-4 py-3 rounded-2xl bg-bg-secondary border border-border-subtle flex gap-1.5 items-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-bounce" />
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-bounce [animation-delay:0.2s]" />
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-bounce [animation-delay:0.4s]" />
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="p-3 bg-bg-secondary border-t border-border-subtle shrink-0">
            <div className="relative flex items-center">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask a cybersecurity question..."
                className="w-full bg-bg-primary border border-border-subtle rounded-xl pl-3 pr-10 py-2.5 text-sm text-text-primary focus:outline-none focus:border-accent-cyan resize-none overflow-hidden"
                rows={1}
              />
              <button
                onClick={handleSend}
                disabled={isLoading || !input.trim()}
                className="absolute right-1.5 p-1.5 bg-accent-cyan text-bg-primary rounded-lg disabled:opacity-40 disabled:bg-bg-tertiary transition-colors"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
