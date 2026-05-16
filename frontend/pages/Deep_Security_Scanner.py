# frontend/pages/Deep_Security_Scanner.py
"""Deep Security Scanner — rewritten with clean architecture."""
import sys, time, json
from pathlib import Path
from datetime import datetime, timezone

import streamlit as st
import pandas as pd

_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from frontend.api_utils import get_client, run_api_call
from frontend.ui_components import apply_custom_css, render_topbar, render_api_error
from frontend.scanner_styles import SCANNER_CSS

# ── Helpers ──────────────────────────────────────────────────────
def _grade_class(grade):
    if not grade:
        return "grade-b"
    g = str(grade).lower().replace("+", "-plus")
    return f"grade-{g}"

def _sev_class(sev):
    return f"sev-{(sev or 'low').lower()}"

def _posture_color(score):
    if score >= 80: return "#22c55e"
    if score >= 60: return "#38bdf8"
    if score >= 40: return "#eab308"
    return "#ef4444"

def _init_state():
    for k, v in {
        "deep_scan_result": None, "deep_scan_analysis": None,
        "deep_scan_target": "", "deep_scan_running": False,
        "deep_scan_history": [], "deep_scan_client_offering": None,
        "total_vulns_found": 0, "total_critical_found": 0,
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v

# ── Section Renderers ────────────────────────────────────────────
def _render_hero():
    history = st.session_state.get("deep_scan_history", [])
    scans = len(history)
    vulns = st.session_state.get("total_vulns_found", 0)
    crits = st.session_state.get("total_critical_found", 0)
    avg = round(sum(h.get("score", 0) for h in history) / max(len(history), 1)) if history else 0
    st.markdown(f"""
    <div class="hero-banner">
        <div class="hero-title">Deep Security Intelligence Platform</div>
        <div class="hero-subtitle">Enterprise-grade reconnaissance · AI-powered vulnerability analysis</div>
        <div class="stats-strip">
            <div class="stat-item"><span class="stat-value">{scans}</span><span class="stat-label">Scans Run</span></div>
            <div class="stat-item"><span class="stat-value">{vulns}</span><span class="stat-label">Vulns Found</span></div>
            <div class="stat-item"><span class="stat-value">{crits}</span><span class="stat-label">Critical</span></div>
            <div class="stat-item"><span class="stat-value">{avg}</span><span class="stat-label">Avg Risk</span></div>
        </div>
    </div>""", unsafe_allow_html=True)

def _render_input():
    target = st.text_input("🎯 Target (domain, IP, or URL)", placeholder="example.com")
    is_auth = bool(st.session_state.get("auth_token"))
    if not is_auth:
        st.warning("🔒 Sign in from the main dashboard to run scans.")
    col1, col2 = st.columns([3, 1])
    with col1:
        clicked = st.button("🚀 Launch Deep Scan", type="primary", disabled=not is_auth, use_container_width=True)
    with col2:
        quick = st.checkbox("Quick scan", value=True)
    st.caption("🛡️ Safe read-only reconnaissance only. No exploitation attempted.")
    return target, clicked, is_auth

def _execute_scan(target):
    client = get_client()
    if not client:
        st.error("API client not available.")
        return False
    st.session_state["deep_scan_running"] = True
    try:
        scan_result = client.deep_scan(target)
        if not scan_result:
            st.error("Scan returned no data. Check the backend is running on port 8000.")
            st.session_state["deep_scan_running"] = False
            return False
        if "error" in scan_result and not scan_result.get("overall_risk_score") and not scan_result.get("open_ports"):
            st.error(f"Scan failed: {scan_result.get('error', 'Unknown error')}")
            st.session_state["deep_scan_running"] = False
            return False
        st.session_state["deep_scan_result"] = scan_result
        st.session_state["deep_scan_target"] = target
        # AI analysis
        analysis, offering = {}, {}
        try:
            resp = client.analyze_scan(scan_result)
            if resp:
                analysis = resp.get("analysis", {})
                offering = resp.get("client_offering", {})
        except Exception as e:
            st.warning(f"AI analysis unavailable (scan data still shown): {str(e)[:120]}")
        st.session_state["deep_scan_analysis"] = analysis
        st.session_state["deep_scan_client_offering"] = offering
        # Counters
        v = len(analysis.get("vulnerabilities", []))
        c = sum(1 for x in analysis.get("vulnerabilities", []) if x.get("severity") == "Critical")
        st.session_state["total_vulns_found"] = st.session_state.get("total_vulns_found", 0) + v
        st.session_state["total_critical_found"] = st.session_state.get("total_critical_found", 0) + c
        # Ensure risk score + grade always present
        # Ensure risk score + grade are always present (fallback compute if backend omitted them)
        risk_score = scan_result.get("overall_risk_score")
        risk_grade = scan_result.get("risk_grade")
        if risk_score is None:
            sev = scan_result.get("severity_counts", {})
            risk_score = min(100, (sev.get("Critical",0)*20 + sev.get("High",0)*12 + sev.get("Medium",0)*6 + sev.get("Low",0)*2 + len(scan_result.get("critical_findings",[]))*8))
            scan_result["overall_risk_score"] = risk_score
        if not risk_grade:
            if risk_score <= 10:   risk_grade = "A+"
            elif risk_score <= 20: risk_grade = "A"
            elif risk_score <= 35: risk_grade = "B"
            elif risk_score <= 55: risk_grade = "C"
            elif risk_score <= 75: risk_grade = "D"
            else:                  risk_grade = "F"
            scan_result["risk_grade"] = risk_grade
        st.session_state["deep_scan_result"] = scan_result
        if "deep_scan_history" not in st.session_state:
            st.session_state["deep_scan_history"] = []
        st.session_state["deep_scan_history"].append({
            "target": target, "risk_grade": risk_grade,
            "score": risk_score, "timestamp": datetime.utcnow().isoformat(), "vuln_count": v,
        })
        st.session_state["deep_scan_running"] = False
        return True
    except Exception as e:
        st.error(f"Scan error: {str(e)[:300]}")
        st.session_state["deep_scan_running"] = False
        return False

# ── Results Dashboard ────────────────────────────────────────────
def _render_scorecard(sr, analysis):
    score = sr.get("overall_risk_score", 0)
    grade = sr.get("risk_grade", "?")
    gc = _grade_class(grade)
    posture = analysis.get("security_posture_breakdown", {})
    st.markdown(f"""
    <div class="gauge-card">
        <div style="font-size:3rem;font-weight:800;font-family:'JetBrains Mono',monospace;color:#e2e8f0">{score}</div>
        <div style="font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:2px">Risk Score</div>
        <div class="grade-badge {gc}">{grade}</div>
    </div>""", unsafe_allow_html=True)
    cats = [("Network Security", "network_security"), ("Application Security", "application_security"),
            ("SSL/TLS Hygiene", "ssl_tls_hygiene"), ("Header Security", "header_security"),
            ("Info Disclosure", "information_disclosure")]
    for label, key in cats:
        val = posture.get(key, 50)
        col = _posture_color(val)
        st.markdown(f"""<div class="posture-row">
            <span class="posture-label">{label}</span>
            <div class="posture-bar-bg"><div class="posture-bar-fill" style="width:{val}%;background:{col}"></div></div>
            <span class="posture-score" style="color:{col}">{val}</span>
        </div>""", unsafe_allow_html=True)

def _render_summary(sr, analysis):
    ip = sr.get("resolved_ip", "N/A")
    ports = sr.get("ports", {})
    ssl = sr.get("ssl", {})
    whois_d = sr.get("whois", {})
    open_c = ports.get("open_count", 0) if ports.get("status") == "completed" else "N/A"
    ssl_st = "✅ Valid" if ssl.get("status") == "completed" and ssl.get("certificate", {}).get("is_valid") else "⚠️ Issues"
    if ssl.get("status") == "failed":
        ssl_st = "❌ Failed"
    expiry = whois_d.get("expiry_date", "N/A") if whois_d.get("status") == "completed" else "N/A"
    for lbl, val in [("Resolved IP", ip), ("Open Ports", open_c), ("SSL Status", ssl_st), ("Domain Expiry", expiry)]:
        st.markdown(f'<div class="metric-card"><div class="metric-card-label">{lbl}</div><div class="metric-card-value">{val}</div></div>', unsafe_allow_html=True)
    # Executive summary
    risk = analysis.get("risk_level", "Medium")
    summary = analysis.get("executive_summary", f"Security assessment of {sr.get('target', 'Unknown')}.")
    sev_c = {"Critical": "#ef4444", "High": "#f59e0b", "Medium": "#eab308", "Low": "#38bdf8"}.get(risk, "#94a3b8")
    st.markdown(f'<div style="padding:12px;border-left:4px solid {sev_c};background:rgba(0,0,0,.2);border-radius:8px;margin-top:12px"><span style="color:{sev_c};font-weight:700">{risk}</span> <span style="color:#cbd5e1;font-size:.85rem">{summary}</span></div>', unsafe_allow_html=True)

def _render_critical_findings(sr):
    findings = sr.get("critical_findings", [])
    if not findings:
        st.success("✅ No critical findings detected.")
        return
    st.warning(f"⚠️ {len(findings)} critical/high findings detected")
    for f in findings[:8]:
        st.markdown(f'<div class="critical-card"><span class="critical-card-icon">🔴</span><span class="critical-card-text">{f}</span></div>', unsafe_allow_html=True)

def _render_vuln_table(analysis):
    vulns = analysis.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerabilities identified in this scan.")
        return
    st.markdown("### 🔍 Identified Vulnerabilities")
    for v in vulns:
        sev = v.get("severity", "Low")
        sc = _sev_class(sev)
        with st.expander(f"[{sev}] {v.get('title', 'Unknown')} — {v.get('category', 'General')}", expanded=(sev in ("Critical", "High"))):
            st.markdown(f'<span class="sev-badge {sc}">{sev}</span> CVSS: {v.get("cvss_score", "N/A")}', unsafe_allow_html=True)
            st.write(f"**Description:** {v.get('description', 'N/A')}")
            if v.get("technical_detail"):
                st.write(f"**Technical Detail:** {v['technical_detail']}")
            if v.get("exploitation_scenario"):
                st.write(f"**Exploitation:** {v['exploitation_scenario']}")
            if v.get("remediation"):
                st.success(f"**Fix:** {v['remediation']}")
            refs = v.get("references", [])
            if refs:
                st.caption("Refs: " + ", ".join(refs))

def _render_detailed_tabs(sr, analysis):
    st.markdown("### 📊 Detailed Analysis")
    tabs = st.tabs(["Ports", "SSL/TLS", "Headers", "Technologies", "DNS", "WHOIS", "Compliance", "Attack Vectors"])

    with tabs[0]:
        ports = sr.get("ports", {})
        if ports.get("status") == "completed":
            op = ports.get("open_ports", [])
            if op:
                df = pd.DataFrame(op)
                st.dataframe(df[["port", "service", "banner", "risk_description"]], use_container_width=True, hide_index=True)
            else:
                st.success("No open ports found.")
        else:
            st.warning(f"Port scan failed: {ports.get('error', 'Unknown')}")

    with tabs[1]:
        ssl = sr.get("ssl", {})
        if ssl.get("status") == "completed":
            cert = ssl.get("certificate", {})
            proto = ssl.get("protocol", {})
            ciph = ssl.get("cipher", {})
            c1, c2 = st.columns(2)
            c1.metric("Protocol", proto.get("version", "N/A"))
            c1.metric("Health Score", f"{ssl.get('health_score', 0)}/100")
            c1.metric("HSTS", "✅ Yes" if ssl.get("hsts_enabled") else "❌ No")
            c2.metric("Valid", "✅" if cert.get("is_valid") else "❌")
            c2.metric("Self-Signed", "⚠️ Yes" if cert.get("is_self_signed") else "✅ No")
            c2.metric("Days Left", cert.get("days_remaining", "N/A"))
            for f in ssl.get("findings", []):
                st.warning(f"[{f.get('severity')}] {f.get('title')}: {f.get('description')}")
        else:
            st.warning(f"SSL audit failed: {ssl.get('error', 'Unknown')}")

    with tabs[2]:
        hd = sr.get("http_headers", {})
        if hd.get("status") == "completed":
            st.write(f"**Missing:** {hd.get('total_missing', 0)} | **Critical Missing:** {hd.get('missing_critical_count', 0)}")
            headers = hd.get("headers", {})
            for name, data in headers.items():
                icon = "✅" if data.get("is_present") else "❌"
                risk = data.get("risk_level", "Low")
                st.write(f"{icon} **{name}** — Risk: {risk}")
            if hd.get("cors_issues"):
                st.error(f"CORS Issues: {', '.join(hd['cors_issues'])}")
            if hd.get("cookie_issues"):
                st.warning(f"Cookie Issues: {len(hd['cookie_issues'])} found")
                for ci in hd["cookie_issues"]:
                    st.caption(f"  • {ci.get('cookie', '?')}: {ci.get('issue', '?')}")
            if hd.get("sensitive_files"):
                st.error(f"Sensitive Files: {', '.join(hd['sensitive_files'])}")
        else:
            st.warning(f"Header scan failed: {hd.get('error', 'Unknown')}")

    with tabs[3]:
        tech = sr.get("technologies", {})
        if tech.get("status") == "completed":
            for lbl, key in [("Web Server", "web_server"), ("Framework", "backend_framework"), ("CMS", "cms"), ("CDN", "cdn")]:
                val = tech.get(key)
                if val:
                    st.write(f"**{lbl}:** `{val}`")
            if tech.get("waf_detected"):
                st.success(f"🛡️ WAF Detected: {tech.get('waf_name', 'Unknown')}")
            else:
                st.info("No common WAF/CDN fingerprint was observed in response headers. This does not prove the absence of edge protection.")
            for vr in tech.get("version_risks", []):
                st.warning(f"⚠️ {vr.get('detail', '')}")
        else:
            st.info("Technology detection unavailable.")

    with tabs[4]:
        dns = sr.get("dns", {})
        if dns.get("status") == "completed":
            c1, c2 = st.columns(2)
            c1.write(f"**SPF:** {dns.get('spf_status', 'N/A')}")
            c1.write(f"**DKIM:** {'✅ Found' if dns.get('dkim_found') else '❌ Not Found'}")
            c1.write(f"**DMARC:** {dns.get('dmarc_policy', 'N/A')}")
            c2.write(f"**DNSSEC:** {'✅' if dns.get('dnssec_enabled') else '❌'}")
            c2.write(f"**Zone Transfer:** {'🔴 VULNERABLE' if dns.get('zone_transfer', {}).get('successful') else '✅ Protected'}")
            if dns.get("ns_records"):
                st.write(f"**NS Records:** {', '.join(dns['ns_records'][:5])}")
            if dns.get("mx_records"):
                st.write(f"**MX Records:** {', '.join(str(m) for m in dns['mx_records'][:5])}")
            if dns.get("takeover_risks"):
                for t in dns["takeover_risks"]:
                    st.error(f"🔴 Subdomain takeover risk: {t}")
        else:
            st.warning(f"DNS scan failed: {dns.get('error', 'Unknown')}")

    with tabs[5]:
        wh = sr.get("whois", {})
        if wh.get("status") == "completed":
            for lbl, key in [("Registrar", "registrar"), ("Created", "creation_date"), ("Expires", "expiry_date"), ("Organization", "org"), ("Country", "country")]:
                st.write(f"**{lbl}:** {wh.get(key, 'N/A')}")
            if wh.get("domain_expiring_soon"):
                st.error(f"⚠️ Domain expires in {wh.get('days_until_expiry', '?')} days!")
            ns = wh.get("name_servers", [])
            if ns:
                st.write(f"**Name Servers:** {', '.join(ns[:5])}")
        else:
            st.warning(f"WHOIS lookup failed: {wh.get('error', 'Unknown')}")

    with tabs[6]:
        comp = analysis.get("compliance_gaps", {})
        owasp = comp.get("owasp_top_10", [])
        st.write(f"**OWASP Top 10 (2021)** › {', '.join(owasp) if owasp else 'None identified'}")
        st.write(f"**PCI DSS** › {comp.get('pci_dss', 'Not assessed')}")
        st.write(f"**ISO 27001** › {', '.join(comp.get('iso27001_gaps', [])) or 'None identified'}")
        st.write(f"**GDPR Relevance** › {comp.get('gdpr_relevant', 'Not assessed')}")

    with tabs[7]:
        avs = analysis.get("attack_vectors", [])
        if avs:
            for av in avs:
                lh = av.get("likelihood", "Medium")
                imp = av.get("impact", "Medium")
                color = "#ef4444" if lh == "High" else "#f59e0b" if lh == "Medium" else "#38bdf8"
                st.markdown(f'<div style="padding:10px;border-left:3px solid {color};background:rgba(0,0,0,.15);border-radius:6px;margin-bottom:8px"><strong style="color:{color}">{av.get("vector","Unknown")}</strong> <span style="color:#64748b;font-size:.75rem">Likelihood: {lh} | Impact: {imp}</span><br/><span style="color:#cbd5e1;font-size:.85rem">{av.get("description","")}</span></div>', unsafe_allow_html=True)
        else:
            st.info("No significant attack vectors identified.")

def _render_roadmap(analysis):
    roadmap = analysis.get("remediation_roadmap", [])
    if not roadmap:
        return
    st.markdown("### 🗺️ Remediation Roadmap")
    for item in roadmap:
        pri = item.get("priority", "?")
        action = item.get("action", "N/A")
        effort = item.get("effort", "Medium").lower()
        impact = item.get("impact", "Medium")
        ec = f"effort-{effort}" if effort in ("low", "medium", "high") else "effort-medium"
        st.markdown(f"""<div class="roadmap-item">
            <div class="roadmap-num">{pri}</div>
            <div class="roadmap-content">
                <div class="roadmap-action">{action}</div>
                <div><span class="effort-badge {ec}">Effort: {effort}</span> <span class="effort-badge effort-{'low' if impact in ('Critical','High') else 'medium'}">Impact: {impact}</span></div>
            </div>
        </div>""", unsafe_allow_html=True)

def _render_export(sr, analysis, target):
    st.markdown("### 📥 Export & Actions")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("📋 Copy JSON Summary", use_container_width=True):
            st.code(json.dumps({"target": target, "risk_score": sr.get("overall_risk_score"), "risk_grade": sr.get("risk_grade"), "severity_counts": sr.get("severity_counts")}, indent=2))
    with c2:
        try:
            client = get_client()
            if client and st.button("📄 Download HTML Report", use_container_width=True):
                with st.spinner("Generating report..."):
                    html = client.export_report(target, sr, analysis)
                    st.download_button("💾 Save Report", data=html, file_name=f"report_{target}.html", mime="text/html")
        except Exception:
            st.caption("Report export unavailable.")

def _render_results():
    sr = st.session_state.get("deep_scan_result")
    analysis = st.session_state.get("deep_scan_analysis", {})
    target = st.session_state.get("deep_scan_target", "")
    if not sr:
        return
    st.markdown("---")
    st.markdown(f"## Results: `{target}`")
    c1, c2 = st.columns([1, 1])
    with c1:
        _render_scorecard(sr, analysis)
    with c2:
        _render_summary(sr, analysis)
    st.markdown("---")
    _render_critical_findings(sr)
    st.markdown("---")
    _render_vuln_table(analysis)
    st.markdown("---")
    _render_detailed_tabs(sr, analysis)
    st.markdown("---")
    _render_roadmap(analysis)
    st.markdown("---")
    _render_export(sr, analysis, target)

# ── Main Entry Point ─────────────────────────────────────────────
def render_deep_security_scanner():
    st.title("🔍 Deep Security Scanner")
    st.markdown(SCANNER_CSS, unsafe_allow_html=True)
    _init_state()
    _render_hero()

    if not st.session_state.get("auth_token"):
        st.warning("🔒 **Sign in required.** Go to the main dashboard → **Login** tab → Create Admin → Sign In.")
        st.info("The Deep Security Scanner requires authentication. All scans are safe, read-only reconnaissance.")
        # Still show scan history if any exists
        history = st.session_state.get("deep_scan_history", [])
        if history:
            st.markdown("---")
            st.markdown("**Previous Scan History (this session)**")
            st.dataframe(
                pd.DataFrame(history).rename(columns={
                    "target": "Target", "risk_grade": "Grade",
                    "score": "Risk Score", "vuln_count": "Vulns", "timestamp": "Time"
                }),
                use_container_width=True, hide_index=True
            )
        return

    target, clicked, is_auth = _render_input()
    if clicked and target and is_auth:
        with st.spinner("🔍 Running comprehensive security scan — this may take 1–2 minutes..."):
            success = _execute_scan(target)
        if success:
            st.rerun()

    if st.session_state.get("deep_scan_result"):
        _render_results()
    elif not st.session_state.get("deep_scan_running"):
        history = st.session_state.get("deep_scan_history", [])
        if history:
            st.markdown("---")
            st.markdown("### 📋 Scan History")
            hist_df = pd.DataFrame(history)
            st.dataframe(
                hist_df.rename(columns={
                    "target": "Target", "risk_grade": "Grade",
                    "score": "Risk Score", "vuln_count": "Vulns", "timestamp": "Time"
                }),
                use_container_width=True, hide_index=True
            )
            if st.button("🗑️ Clear History", type="secondary"):
                st.session_state["deep_scan_history"] = []
                st.session_state["deep_scan_result"] = None
                st.session_state["total_vulns_found"] = 0
                st.session_state["total_critical_found"] = 0
                st.rerun()
        else:
            st.info("Enter a target above and click **Launch Deep Scan** to begin.")

# ── Streamlit page execution ─────────────────────────────────────
try:
    apply_custom_css()
except Exception:
    pass
try:
    render_topbar()
except Exception:
    pass
render_deep_security_scanner()
