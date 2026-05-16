"""CSS styles for the Deep Security Scanner page."""

SCANNER_CSS = """
<style>
.hero-banner{position:relative;background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);border:1px solid rgba(56,189,248,.15);border-radius:16px;padding:48px 40px;margin-bottom:32px;overflow:hidden}
.hero-banner::after{content:'';position:absolute;bottom:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,#38bdf8,transparent);animation:scan-line 3s ease-in-out infinite}
@keyframes scan-line{0%,100%{opacity:.3;transform:scaleX(.5)}50%{opacity:1;transform:scaleX(1)}}
.hero-title{font-family:'Space Grotesk','Outfit',sans-serif;font-size:2.2rem;font-weight:700;color:#e2e8f0;margin:0 0 8px}
.hero-subtitle{font-size:1rem;color:#94a3b8;margin:0 0 24px;font-weight:300}
.stats-strip{display:flex;gap:32px;flex-wrap:wrap}
.stat-item{text-align:center}
.stat-value{font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:700;color:#38bdf8;display:block}
.stat-label{font-size:.7rem;letter-spacing:1.5px;text-transform:uppercase;color:#64748b;margin-top:4px}
.gauge-card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:32px;text-align:center}
.grade-badge{display:inline-block;padding:8px 24px;border-radius:8px;font-size:1.5rem;font-weight:700;font-family:'JetBrains Mono',monospace;margin-top:16px}
.grade-a-plus,.grade-a{background:rgba(34,197,94,.12);color:#22c55e;border:2px solid rgba(34,197,94,.3)}
.grade-b{background:rgba(56,189,248,.12);color:#38bdf8;border:2px solid rgba(56,189,248,.3)}
.grade-c{background:rgba(234,179,8,.12);color:#eab308;border:2px solid rgba(234,179,8,.3)}
.grade-d{background:rgba(245,158,11,.12);color:#f59e0b;border:2px solid rgba(245,158,11,.3)}
.grade-f{background:rgba(239,68,68,.12);color:#ef4444;border:2px solid rgba(239,68,68,.3)}
.posture-row{display:flex;align-items:center;gap:12px;margin:10px 0}
.posture-label{font-size:.75rem;color:#94a3b8;min-width:130px;text-align:right}
.posture-bar-bg{flex:1;height:6px;background:#1e293b;border-radius:3px;overflow:hidden}
.posture-bar-fill{height:100%;border-radius:3px;transition:width .8s ease}
.posture-score{font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:700;min-width:30px}
.metric-card{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:16px 20px;margin-bottom:12px}
.metric-card-label{font-size:.7rem;letter-spacing:1.5px;text-transform:uppercase;color:#64748b;margin-bottom:4px}
.metric-card-value{font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;color:#e2e8f0}
.critical-card{background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.2);border-left:4px solid #ef4444;border-radius:8px;padding:16px 20px;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.critical-card-icon{font-size:1.2rem;flex-shrink:0}
.critical-card-text{font-size:.85rem;color:#fca5a5;line-height:1.4}
.sev-critical{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.sev-high{background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3)}
.sev-medium{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3)}
.sev-low{background:rgba(56,189,248,.15);color:#38bdf8;border:1px solid rgba(56,189,248,.3)}
.sev-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.7rem;font-weight:600;letter-spacing:.5px;text-transform:uppercase}
.info-card{background:#111827;border:1px solid #1e293b;border-radius:10px;padding:20px;margin-bottom:12px}
.info-card-title{font-size:.75rem;letter-spacing:1.5px;text-transform:uppercase;color:#38bdf8;margin-bottom:12px;font-weight:600}
.info-card-content{font-size:.85rem;color:#cbd5e1;line-height:1.6}
.roadmap-item{display:flex;align-items:flex-start;gap:16px;padding:14px 0;border-bottom:1px solid #1e293b}
.roadmap-num{width:28px;height:28px;border-radius:50%;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-size:.75rem;font-weight:700;color:#38bdf8;flex-shrink:0}
.roadmap-content{flex:1}
.roadmap-action{font-size:.85rem;color:#e2e8f0;margin-bottom:6px}
.effort-badge{padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase}
.effort-low{background:rgba(34,197,94,.1);color:#22c55e}
.effort-medium{background:rgba(234,179,8,.1);color:#eab308}
.effort-high{background:rgba(239,68,68,.1);color:#ef4444}
.finding-row{padding:12px 16px;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:12px}
.finding-row:hover{background:rgba(56,189,248,.03)}
</style>
"""
