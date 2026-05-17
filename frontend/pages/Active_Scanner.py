import sys
import streamlit as st
import pandas as pd
from pathlib import Path

# Guarantee the project root (PFAI/) is on sys.path on Windows
_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from frontend.api_utils import get_client, run_api_call, fetch_model_info
from frontend.ui_components import apply_custom_css, render_topbar, render_api_error

def render_active_scanner():
    apply_custom_css()
    render_topbar()
    st.title("🎯 Active Target Scanner")
    st.markdown("""
    **Welcome to the Active Scanner!** 
    This tool allows you to safely check a computer or website (like `192.168.1.5` or `example.com`) to see what "doors" (ports) are open and what security risks might exist. 
    
    *Note: We only perform safe reconnaissance (looking around). We do not launch actual attacks like DDoS or Bruteforcing.*
    """)

    with st.expander("📖 What is Port Scanning?"):
        st.write("""
        Imagine a computer is a house, and **ports** are the doors and windows. 
        - Port 80 (HTTP) is like the front door for web traffic.
        - Port 22 (SSH) is like a secure back door for administrators.
        
        If a door is open and the lock (password/security) is weak, hackers can break in. This scanner checks which doors are open so you can secure them!
        """)

    target = st.text_input("Enter IP Address or Domain Name (e.g., 127.0.0.1 or google.com)", value=st.session_state.get("scan_target", "127.0.0.1"))

    if st.button("Start Safe Reconnaissance Scan", type="primary"):
        if not target:
            st.error("Please enter a target.")
            return

        st.session_state["scan_target"] = target
        with st.spinner(f"Scanning {target}... This may take a minute as we check common ports and grab banners."):
            client = get_client()
            result, err = run_api_call(client.active_scan, target=target)

        if err:
            render_api_error(err)
            return

        if result is None:
            st.warning(
                "🔐 **Authentication required.** "
                "Please sign in from the **Login** tab to use the Active Scanner."
            )
            return

        if result.get("error"):
            st.error(f"Scan failed: {result['error']}")
            return

        st.session_state["scan_result"] = result
        st.session_state["vuln_analysis"] = None # Reset analysis
        st.rerun()

    result = st.session_state.get("scan_result")
    
    if result:
        st.success("Scan Complete!")

        # 1. DNS & Latency
        st.subheader("🌐 Basic Info (Reconnaissance)")
        col1, col2 = st.columns(2)
        dns_info = result.get("dns", {})
        ip_addr = dns_info.get("ip_address", "N/A")
        latency = f"{result.get('latency_ms', 'N/A')} ms"
        
        col1.markdown(f"""
        <div class="metric-card">
            <div class="section-label">Resolved IP Address</div>
            <h2 style="margin:0; color:#fff;">{ip_addr}</h2>
        </div>
        """, unsafe_allow_html=True)
        
        col2.markdown(f"""
        <div class="metric-card">
            <div class="section-label">Response Time (Latency)</div>
            <h2 style="margin:0; color:#fff;">{latency}</h2>
        </div>
        """, unsafe_allow_html=True)

        # 2. Open Ports
        st.subheader("🚪 Open Ports & Service Banners")
        ports = result.get("ports", [])
        if not ports:
            st.success("No common open ports found. This is usually good for security!")
        else:
            st.warning(f"Found {len(ports)} open port(s).")
            for p in ports:
                with st.expander(f"Port {p['port']} ({p['service']}) - OPEN", expanded=True):
                    st.write(f"**Description:** {p['description']}")
                    if p.get('banner'):
                        st.info(f"**Detected Software Version (Banner):** `{p['banner']}`")
                    else:
                        st.write("**Detected Software Version:** None exposed (Good security practice!)")
                    st.write(f"**General Context:** {p.get('vulnerability_context', 'N/A')}")

        # 3. SSL/TLS Certificate
        st.subheader("🔒 SSL/TLS Certificate (Encryption)")
        ssl_data = result.get("ssl")

        if not ssl_data:
            # Port 443 was not open — no SSL section scanned
            st.info("ℹ️ Port 443 is not open on this target — SSL/TLS inspection was skipped.")
        else:
            ssl_status = ssl_data.get("status", "error")
            cdn_note   = ssl_data.get("cdn_note")
            cdn_protected = ssl_data.get("cdn_protected", False)

            if cdn_protected and cdn_note:
                # CDN or firewall is blocking direct cert inspection
                st.markdown(f"""
                <div style="padding:1rem 1.2rem; border-left:5px solid #f59e0b;
                            background:rgba(245,158,11,0.07); border-radius:8px; margin-bottom:1rem;">
                    <h4 style="margin:0 0 0.4rem 0; color:#f59e0b;">🛡️ CDN / Firewall Detected</h4>
                    <p style="margin:0; font-size:0.95rem; color:#cbd5e1;">{cdn_note}</p>
                </div>
                """, unsafe_allow_html=True)

                if ssl_status == "ok":
                    # We still got a cert (e.g. a Cloudflare edge cert) — show what we have
                    st.markdown("**Edge certificate details (CDN intermediary, not origin):**")
                    col_a, col_b = st.columns(2)
                    col_a.write(f"**Subject:** `{ssl_data.get('subject', 'N/A')}`")
                    col_a.write(f"**Issuer:** `{ssl_data.get('issuer', 'N/A')}`")
                    col_b.write(f"**Expires:** `{ssl_data.get('expires', 'N/A')}`")
                    col_b.write(f"**TLS Version:** `{ssl_data.get('tls_version', 'N/A')}`")
                    col_b.write(f"**Cipher:** `{ssl_data.get('cipher', 'N/A')}`")
                elif ssl_data.get("error"):
                    st.caption(f"Technical detail: {ssl_data['error']}")

            elif ssl_status == "ok":
                # Full cert retrieved — no CDN blocking
                col_a, col_b = st.columns(2)
                col_a.write(f"**Subject:** `{ssl_data.get('subject', 'N/A')}`")
                col_a.write(f"**Issuer:** `{ssl_data.get('issuer', 'N/A')}`")
                col_a.write(f"**Valid From:** `{ssl_data.get('valid_from', 'N/A')}`")
                col_b.write(f"**Expires:** `{ssl_data.get('expires', 'N/A')}`")
                col_b.write(f"**TLS Version:** `{ssl_data.get('tls_version', 'N/A')}`")
                col_b.write(f"**Cipher Suite:** `{ssl_data.get('cipher', 'N/A')}`")
                with st.expander("Raw SSL Data"):
                    st.json(ssl_data)

            else:
                # Some other failure (refused, generic error)
                err_msg = ssl_data.get("error", "SSL inspection failed — reason unknown.")
                st.markdown(f"""
                <div style="padding:1rem 1.2rem; border-left:5px solid #ef4444;
                            background:rgba(239,68,68,0.07); border-radius:8px; margin-bottom:1rem;">
                    <h4 style="margin:0 0 0.4rem 0; color:#ef4444;">❌ SSL Inspection Failed</h4>
                    <p style="margin:0; font-size:0.95rem; color:#cbd5e1;">{err_msg}</p>
                </div>
                """, unsafe_allow_html=True)

            
        # 4. HTTP Headers
        if result.get("http_headers"):
            st.subheader("📄 Web Server Headers")
            st.json(result["http_headers"])

        # 5. WHOIS
        if result.get("whois"):
            st.subheader("🏢 Domain Registration (WHOIS)")
            st.json(result["whois"])

        # 6. Defensive configuration observations
        st.subheader("🛡️ Defensive Configuration Observations")
        st.markdown("We reviewed externally observable controls and exposure indicators. These observations do not verify exploitability.")
        
        configs = result.get("security_configs", [])
        if not configs:
            st.success("✅ No high-signal configuration observations were reported by this non-invasive scan.")
        else:
            for c in configs:
                sev = c.get('severity', 'Medium')
                color = "red" if sev == "Critical" else "orange" if sev == "High" else "yellow"
                st.markdown(f"""
                <div style="padding: 1rem; border-left: 5px solid {color}; background: rgba(255,255,255,0.05); margin-bottom: 1rem; border-radius: 8px;">
                    <h4 style="margin-top: 0; margin-bottom: 0.5rem; color: {color};">⚠️ {c.get('type')} ({sev})</h4>
                    <p style="margin: 0; font-size: 0.95rem;">{c.get('description')}</p>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")
        st.subheader("🧠 Advanced AI Defensive Analysis")
        st.markdown("Review these observations with AI-assisted defensive analysis. Results should be treated as guidance, not exploit verification.")
        
        if st.button("Run Advanced Vulnerability Analysis", type="primary", use_container_width=True):
            with st.spinner("AI is analyzing the scan data for CVEs and misconfigurations..."):
                client = get_client()
                analysis, a_err = run_api_call(client.analyze_vulnerability, payload=result)
                if a_err:
                    st.error("Failed to run analysis.")
                else:
                    st.session_state["vuln_analysis"] = analysis
                    st.rerun()

        analysis = st.session_state.get("vuln_analysis")
        if analysis:
            st.markdown("### 📋 AI Security Audit Report")
            if analysis.get("vulnerabilities_found"):
                st.error("🚨 **Security findings reported**")
            else:
                st.success("✅ **No major findings reported by this limited non-invasive assessment.**")
                
            st.write(f"**Summary:** {analysis.get('summary', 'N/A')}")
            
            findings = analysis.get("findings", [])
            if findings:
                st.markdown("#### Detailed Findings")
                for f in findings:
                    with st.expander(f"Port {f.get('port')} ({f.get('service')}) - {f.get('vulnerability')[:50]}...", expanded=True):
                        st.write(f"**Vulnerability:** {f.get('vulnerability')}")
                        st.write(f"**How it's Exploited:** {f.get('exploitation')}")
                        st.write(f"**How to Fix it:** {f.get('remediation')}")

if __name__ == "__main__":
    apply_custom_css()
    render_active_scanner()
else:
    apply_custom_css()
    render_topbar()
    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the main dashboard (Login tab) to use the Active Scanner.")
        st.info("💡 Go to main dashboard → Login tab → Create Admin → Sign In")
    else:
        render_active_scanner()
