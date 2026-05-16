import sys
import streamlit as st
import pandas as pd
import time
from pathlib import Path

_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from frontend.api_utils import get_client, run_api_call, fetch_model_info
from frontend.ui_components import apply_custom_css, render_topbar, render_api_error

from frontend.pages.Capture_Control import start_capture, stop_capture, get_capture_stats

def render_live_monitor():
    apply_custom_css()
    render_topbar()
    st.title("📡 Live Network Monitor")
    st.markdown("""
    This page shows you what is happening on your network **right now**. 
    It acts like a security camera for your internet connection, watching for suspicious activity.
    """)

    with st.expander("📖 How does this work?"):
        st.write("""
        When you click **Start Live Capture**, our AI starts listening to the traffic flowing through your computer's network card.
        - If someone tries to scan your computer (looking for open doors), we will catch it.
        - If someone tries to guess your passwords (brute force), we will catch it.
        - If a program sends way too much data (potential data theft), we will catch it.
        
        *Don't worry, we only look at the 'envelopes' of the data, not the contents inside!*
        """)

    col1, col2 = st.columns(2)

    stats = get_capture_stats()
    is_running = stats.get('running', False) if isinstance(stats, dict) else False

    with col1:
        if not is_running:
            st.info("The network camera is currently OFF.")
            if st.button("▶️ Start Live Capture", type="primary"):
                with st.spinner("Starting..."):
                    res = start_capture()
                    if res is None or "error" in res:
                        st.error(res["error"] if res else "Backend not reachable.")
                    else:
                        st.success("Started successfully!")
                        time.sleep(1)
                        st.rerun()
        else:
            st.success("🟢 The network camera is ON and watching for threats.")
            if st.button("⏹️ Stop Live Capture", type="secondary"):
                with st.spinner("Stopping..."):
                    res = stop_capture()
                    if res is None or "error" in res:
                        st.error(res["error"] if res else "Backend not reachable.")
                    else:
                        st.success("Stopped successfully!")
                        time.sleep(1)
                        st.rerun()

    with col2:
        flows_count = stats.get('flows_count', 0) if isinstance(stats, dict) else 0
        ip_count = stats.get('ip_count', 0) if isinstance(stats, dict) else 0
        
        st.markdown(f"""
        <div class="metric-card" style="margin-bottom: 1rem;">
            <div class="section-label">Total Connections Monitored</div>
            <h2 style="margin:0; color:#fff;">{flows_count}</h2>
        </div>
        <div class="metric-card">
            <div class="section-label">Devices Tracked</div>
            <h2 style="margin:0; color:#fff;">{ip_count}</h2>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("🚨 Real-Time Threat Alerts")
    
    if st.button("🔄 Refresh Alerts"):
        pass

    client = get_client()
    alerts_data, err = run_api_call(client.get_alerts)

    if err:
        render_api_error(err)
        return

    # Unpack envelope: API returns {"alerts": [...], "total": N}
    if isinstance(alerts_data, dict):
        alert_list = alerts_data.get("alerts", [])
    elif isinstance(alerts_data, list):
        alert_list = alerts_data
    else:
        alert_list = []

    if not alert_list:
        st.success("No threats detected recently! Your network looks safe.")
    else:
        st.warning(f"Found {len(alert_list)} recent alerts!")
        df = pd.DataFrame(alert_list)
        if not df.empty:
            for _, row in df.iterrows():
                severity = row.get('severity', 'Medium')
                color = "🔴" if severity == "High" else "🟡"
                alert_label = row.get('alert_type', 'Suspicious Activity')
                with st.expander(f"{color} {severity} Risk: {alert_label}", expanded=(severity=="High")):
                    st.write(f"**Description:** {row.get('description')}")
                    if row.get('src_ip'):
                        st.write(f"**Source IP:** `{row.get('src_ip')}`")
                    st.write(f"**Time:** {row.get('created_at')}")
                    
                    st.markdown("### 🤖 AI Explanation")
                    st.info("Click 'Analyze with AI' in the Security Center to get a plain-English explanation of this threat.")

if __name__ == "__main__":
    apply_custom_css()
    render_live_monitor()
else:
    apply_custom_css()
    render_topbar()
    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the main dashboard (Login tab) to use the Live Monitor.")
        st.info("💡 Go to main dashboard → Login tab → Create Admin → Sign In")
    else:
        render_live_monitor()

