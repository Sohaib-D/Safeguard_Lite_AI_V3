from __future__ import annotations
# Force reload

import io
import json
import math
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from matplotlib.ticker import MaxNLocator
import streamlit.components.v1 as components

# Add project root to path so imports work when running with streamlit
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from frontend.logging_config import configure_logger
from frontend.sample_data import ATTACK_PROFILES, generate_live_records

# Force reload of modules to prevent Streamlit caching issues
for mod in ["frontend.api_client", "frontend.ui_components", "frontend.api_utils"]:
    if mod in sys.modules:
        del sys.modules[mod]
from frontend.api_client import APIClientError, SafeguardAPIClient
from frontend.api_utils import get_client, run_api_call, fetch_model_info
from frontend.ui_components import apply_custom_css, render_sidebar, render_topbar, render_api_error, build_prediction_results_frame, render_first_row_explanation

st.set_page_config(
    page_title="Safeguard-AI Lite",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)
logger = configure_logger("safeguard.frontend", "logs/frontend.log")


def init_state() -> None:
    st.session_state.setdefault(
        "api_base_url",
        os.environ.get("SAFEGUARD_API_BASE_URL", "http://127.0.0.1:8000"),
    )
    st.session_state.setdefault("auth_token", None)
    st.session_state.setdefault("auth_user", None)
    st.session_state.setdefault("model_info_cache", None)
    st.session_state.setdefault("latest_prediction_result", None)
    st.session_state.setdefault("latest_upload_result", None)
    st.session_state.setdefault("live_history", [])
    st.session_state.setdefault("live_recent_events", [])
    st.session_state.setdefault("live_alerts", [])
    st.session_state.setdefault("show_create_admin", False)
    # Deep scan state
    st.session_state.setdefault("deep_scan_result", None)
    st.session_state.setdefault("deep_scan_analysis", None)
    st.session_state.setdefault("deep_scan_target", "")
    st.session_state.setdefault("deep_scan_running", False)
    st.session_state.setdefault("deep_scan_history", [])
    st.session_state.setdefault("deep_scan_client_offering", None)
    st.session_state.setdefault("total_vulns_found", 0)
    st.session_state.setdefault("total_critical_found", 0)
    # Active scanner state
    st.session_state.setdefault("scan_result", None)
    st.session_state.setdefault("scan_target", "")


def serialize_live_history(history: list[dict]) -> list[dict]:
    """Convert session-state live events into a cache-safe payload."""
    serialized: list[dict] = []
    for item in history:
        serialized.append(
            {
                "timestamp": (
                    item["timestamp"].isoformat()
                    if isinstance(item.get("timestamp"), datetime)
                    else str(item.get("timestamp"))
                ),
                "predicted_label": item.get("predicted_label"),
                "confidence": item.get("confidence"),
                "severity": item.get("severity"),
            }
        )
    return serialized


@st.cache_data(show_spinner=False)
def compute_analytics_payload(
    live_history_payload: list[dict], stats_payload: dict | None
) -> dict:
    """Build cached analytics summaries and chart frames."""
    events_df = pd.DataFrame(live_history_payload)
    if not events_df.empty:
        events_df["timestamp"] = pd.to_datetime(events_df["timestamp"], errors="coerce")
        events_df = events_df.dropna(subset=["timestamp"])

    total_scans = (
        int(stats_payload["total_predictions"]) if stats_payload else len(events_df)
    )
    if not events_df.empty:
        attack_mask = events_df["predicted_label"].astype(str).str.lower() != "normal"
        attack_count = int(attack_mask.sum())
        percent_attacks = (
            round((attack_count / len(events_df)) * 100, 2) if len(events_df) else 0.0
        )
        attack_counts = (
            events_df.loc[attack_mask, "predicted_label"]
            .value_counts()
            .rename_axis("attack_type")
            .reset_index(name="count")
        )
        daily_trend = (
            events_df.assign(day=lambda df: df["timestamp"].dt.floor("D"))
            .groupby("day")
            .size()
            .reset_index(name="events")
            .sort_values("day")
        )
    else:
        attack_counts = pd.DataFrame(columns=["attack_type", "count"])
        daily_trend = pd.DataFrame(columns=["day", "events"])
        label_counts = (stats_payload or {}).get("predictions_by_label", {})
        normal_count = int(label_counts.get("Normal", 0))
        attack_count = max(total_scans - normal_count, 0)
        percent_attacks = (
            round((attack_count / total_scans) * 100, 2) if total_scans else 0.0
        )
        attack_counts = (
            pd.DataFrame(
                [
                    {"attack_type": key, "count": value}
                    for key, value in label_counts.items()
                    if str(key).lower() != "normal"
                ]
            )
            .sort_values(by="count", ascending=False)
            .reset_index(drop=True)
        )

    top_attack_types = attack_counts.head(3)
    top_attack_summary = (
        ", ".join(
            f"{row.attack_type} ({int(row.count)})"
            for row in top_attack_types.itertuples()
        )
        or "No attack labels yet"
    )

    return {
        "events_df": events_df,
        "attack_counts": attack_counts,
        "daily_trend": daily_trend,
        "total_scans": total_scans,
        "percent_attacks": percent_attacks,
        "top_attack_summary": top_attack_summary,
    }


def append_live_events(result: dict) -> None:
    """Persist live events and alerts in session state."""
    for item in result.get("predictions", []):
        event = {
            "timestamp": datetime.utcnow(),
            "predicted_label": item["predicted_label"],
            "confidence": item.get("confidence") or 0.0,
            "severity": item.get(
                "recommendation_severity",
                "Alert" if item["predicted_label"] != "Normal" else "Normal",
            ),
            "recommendations": item.get("recommendations", []),
        }
        st.session_state["live_history"].append(event)
        st.session_state["live_recent_events"].append(event)
        if event["severity"] == "Alert":
            st.session_state["live_alerts"].append(event)

    st.session_state["live_history"] = st.session_state["live_history"][-200:]
    st.session_state["live_recent_events"] = st.session_state["live_recent_events"][
        -30:
    ]
    st.session_state["live_alerts"] = st.session_state["live_alerts"][-20:]


def render_live_dashboard(
    table_placeholder, alerts_placeholder, charts_placeholder
) -> None:
    """Render recent live events, alerts, and compact charts into placeholders."""
    events_df = pd.DataFrame(st.session_state.get("live_recent_events", []))
    alerts_df = pd.DataFrame(st.session_state.get("live_alerts", []))

    with table_placeholder.container():
        st.markdown("**Recent Events**")
        if events_df.empty:
            st.info("No streamed events yet. Run a simulation or start the fake live feed.")
        else:
            display_df = events_df.copy()
            display_df["timestamp"] = display_df["timestamp"].astype(str)
            st.dataframe(
                display_df.sort_values(by="timestamp", ascending=False),
                use_container_width=True,
                hide_index=True,
            )

    with alerts_placeholder.container():
        st.markdown("**Recent Alerts**")
        if alerts_df.empty:
            st.success("✅ No active alerts in the recent event window.")
        else:
            display_df = alerts_df.copy()
            display_df["timestamp"] = display_df["timestamp"].astype(str)
            display_df["recommendations"] = display_df["recommendations"].map(
                lambda items: " | ".join(items) if isinstance(items, list) else items
            )
            st.dataframe(
                display_df.sort_values(by="timestamp", ascending=False),
                use_container_width=True,
                hide_index=True,
            )

    with charts_placeholder.container():
        if events_df.empty:
            return

        col1, col2 = st.columns(2)
        with col1:
            label_counts = events_df["predicted_label"].value_counts()
            colors = ["#38bdf8", "#fb7185", "#fbbf24", "#34d399", "#a78bfa",
                      "#f97316", "#e879f9", "#22d3ee"]
            fig, ax = plt.subplots(figsize=(5, 5))
            fig.patch.set_facecolor("#0f172a")
            ax.set_facecolor("#0f172a")
            wedges, texts, autotexts = ax.pie(
                label_counts.values,
                labels=label_counts.index,
                autopct="%1.1f%%",
                startangle=90,
                colors=colors[:len(label_counts)],
            )
            for t in texts + autotexts:
                t.set_color("#e2e8f0")
            ax.set_title("Recent Attack Mix", color="#e2e8f0", fontsize=13, pad=12)
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)

        with col2:
            st.markdown("**2-Second Event Timeline**")
            timeline_df = events_df.copy()
            timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"])
            grouped = (
                timeline_df
                .assign(second=lambda df: df["timestamp"].dt.floor("2s"))
                .groupby(["second", "predicted_label"])
                .size()
                .unstack(fill_value=0)
                .sort_index()
            )
            if len(grouped) >= 2:
                st.line_chart(grouped)
            elif len(grouped) == 1:
                # Only one time point — use matplotlib bar chart with integer Y-axis
                colors_map = {"Normal": "#34d399", "BruteForce": "#38bdf8",
                              "DDoS": "#fb7185", "PortScan": "#fbbf24"}
                fig, ax = plt.subplots(figsize=(6, 4))
                fig.patch.set_facecolor("#0f172a")
                ax.set_facecolor("#111827")
                x_labels = [t.strftime("%H:%M:%S") for t in grouped.index]
                bar_width = 0.25
                cols = list(grouped.columns)
                for i, col in enumerate(cols):
                    offset = (i - len(cols)/2 + 0.5) * bar_width
                    positions = [j + offset for j in range(len(x_labels))]
                    ax.bar(positions, grouped[col], width=bar_width,
                           label=col, color=colors_map.get(col, "#a78bfa"))
                ax.set_xticks(range(len(x_labels)))
                ax.set_xticklabels(x_labels, color="#e2e8f0")
                ax.yaxis.set_major_locator(MaxNLocator(integer=True))
                ax.set_ylabel("Count", color="#94a3b8")
                ax.set_title("2-Second Event Timeline", color="#e2e8f0", pad=10)
                ax.legend(facecolor="#1e293b", edgecolor="#334155", labelcolor="#e2e8f0")
                ax.tick_params(colors="#e2e8f0")
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                ax.spines["left"].set_color("#334155")
                ax.spines["bottom"].set_color("#334155")
                plt.tight_layout()
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)
            else:
                st.info("Accumulating data…")


def render_login() -> None:
    auth_token = st.session_state.get("auth_token")
    auth_user  = st.session_state.get("auth_user")

    if auth_token and auth_user:
        st.success(f"✅ You are signed in as **{auth_user}**.")
        st.info("You now have full access to all tabs and sidebar tools.")
        if st.button("🚪 Sign Out", type="secondary"):
            st.session_state["auth_token"]       = None
            st.session_state["auth_user"]        = None
            st.session_state["model_info_cache"] = None
            st.rerun()
        return

    st.subheader("Login")
    st.caption("Authenticate to access protected dashboard features.")

    col_form, col_help = st.columns([1, 1])
    with col_form:
        with st.container(border=True):
            st.markdown("**Sign In or Create Account**")
            username = st.text_input("Username", key="login_username", placeholder="e.g. admin")
            password = st.text_input("Password", type="password", key="login_password", placeholder="Your password")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Sign In", type="primary", use_container_width=True):
                    if not username or not password:
                        st.error("Please enter both username and password.")
                    else:
                        result, err = run_api_call(get_client().login, username=username, password=password)
                        if err:
                            render_api_error(err)
                        elif result is None:
                            st.error("❌ Cannot reach backend. Run: `uvicorn backend.api.main:app --reload`")
                        elif "access_token" in result:
                            st.session_state["auth_token"] = result["access_token"]
                            st.session_state["auth_user"]  = result.get("username", username)
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error(f"Login failed: {result.get('detail', 'Invalid credentials')}")
            with c2:
                if st.button("Create Admin", use_container_width=True):
                    if not username or not password:
                        st.error("Enter username and password first.")
                    else:
                        result, err = run_api_call(get_client().create_admin, username=username, password=password)
                        if err:
                            render_api_error(err)
                        elif result is None:
                            st.error("❌ Cannot reach backend.")
                        else:
                            st.success("✅ Admin created! Now click **Sign In**.")

    with col_help:
        with st.container(border=True):
            st.markdown("**ℹ️ First time here?**")
            st.markdown("""
1. Enter any username & password  
2. Click **Create Admin**  
3. Click **Sign In**

**Backend not running?**  
Open a terminal and run:
```
uvicorn backend.api.main:app --reload
```
Then refresh this page.
            """)



def render_home() -> None:
    st.markdown(
        """
        <div class="hero-card">
            <div class="section-label">👋 Welcome to Safeguard-AI Lite!</div>
            <h2 style="margin:0;">Your Personal AI Security Assistant</h2>
            <p style="margin-top:0.6rem;color:#cbd5e1;">
                Think of this as a smart security guard for your network — it watches traffic for suspicious patterns, lets you scan any IP or website for vulnerabilities, and uses AI to classify threats in real-time.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("📖 Getting Started — Start Here!", expanded=True):
        st.markdown("""
**Don't know cybersecurity? No problem — follow these steps:**

| Step | What to Do | Where |
|------|-----------|-------|
| 1 | Start the backend server | Terminal: `uvicorn backend.api.main:app --reload` |
| 2 | Create an account & sign in | **Login** tab (above) |
| 3 | Scan an IP or website | Sidebar → **Deep Security Scanner** |
| 4 | Simulate attacks with AI | **Live Predictions** tab |
| 5 | View all your results | **Statistics** tab |
        """)

    model_info = fetch_model_info()
    stats_result, _ = (
        run_api_call(get_client().stats) if st.session_state.get("auth_token") else (None, None)
    )

    if not model_info:
        st.warning("⚠️ **Backend not connected.** Start it with: `uvicorn backend.api.main:app --reload --port 8000`")
    else:
        st.success("✅ Backend connected — model loaded and ready.")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Model", model_info.get("model_name", "Unavailable") if model_info else "Unavailable")
    c2.metric("Attack Classes", len(model_info.get("label_classes", [])) if model_info else 0)
    c3.metric("Tracked Features", model_info.get("feature_count", 0) if model_info else 0)
    c4.metric("Predictions Logged",
              stats_result.get("total_predictions", 0) if stats_result else 0)

    # Session scan stats
    scan_history = st.session_state.get("deep_scan_history", [])
    if scan_history:
        st.markdown("---")
        st.markdown("### 🔍 This Session")
        s1, s2, s3 = st.columns(3)
        s1.metric("Deep Scans Run", len(scan_history))
        s2.metric("Vulnerabilities Found", st.session_state.get("total_vulns_found", 0))
        s3.metric("Critical Findings", st.session_state.get("total_critical_found", 0))

    if model_info and "label_classes" in model_info:
        st.markdown("---")
        st.markdown("### Model Info")
        left, right = st.columns([1.2, 1])
        with left:
            st.dataframe(
                pd.DataFrame({"Label Classes": model_info["label_classes"]}),
                use_container_width=True, hide_index=True,
            )
        with right:
            schema = model_info.get("raw_input_schema", {})
            st.markdown("**Expected Input Shape**")
            st.write(f"Numeric columns: {len(schema.get('numeric_columns', []))}")
            st.write(f"Categorical columns: {len(schema.get('categorical_columns', []))}")



def render_upload() -> None:
    st.subheader("Upload Dataset")
    st.caption(
        "Upload CSV logs, preview them, send them to `/predict`, "
        "and export the returned predictions."
    )

    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the **Login** tab to upload datasets.")
        return

    uploaded_file = st.file_uploader("Choose CSV", type=["csv"], key="upload_csv")
    predict_file_name = "uploaded_dataset.csv"

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        preview = pd.read_csv(io.BytesIO(file_bytes))
        st.markdown("**Preview**")
        st.dataframe(preview.head(10), use_container_width=True)
        st.caption(f"Rows: {len(preview)} | Columns: {len(preview.columns)}")

        if st.button("Submit to Prediction API", use_container_width=True):
            logger.info(
                "Frontend upload prediction submitted.",
                extra={
                    "event_type": "frontend_upload_predict",
                    "details": {
                        "file_name": uploaded_file.name,
                        "row_count": len(preview),
                    },
                },
            )
            pred_result, pred_err = run_api_call(
                get_client().predict_csv,
                file_name=uploaded_file.name or predict_file_name,
                file_bytes=file_bytes,
            )
            if pred_err:
                render_api_error(pred_err)
            else:
                st.session_state["latest_prediction_result"] = pred_result
                logger.info(
                    "Frontend prediction result received.",
                    extra={
                        "event_type": "frontend_predict_success",
                        "details": {
                            "labels": pred_result.get("summary", {}).get("labels", {})
                        },
                    },
                )
                st.success("Prediction complete.")

        result = st.session_state.get("latest_prediction_result")
        if result:
            st.markdown("**Prediction Results**")
            results_df = build_prediction_results_frame(result)
            if not results_df.empty:
                st.dataframe(results_df, use_container_width=True, hide_index=True)
                csv_bytes = results_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "Download Results as CSV",
                    data=csv_bytes,
                    file_name="prediction_results.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            if result.get("summary", {}).get("recommended_actions"):
                st.markdown("**Batch Recommendations**")
                for suggestion in result["summary"]["recommended_actions"]:
                    st.write(f"- {suggestion}")
            render_first_row_explanation(result)


def render_live_predictions() -> None:
    st.subheader("Live Prediction Simulation")

    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the **Login** tab to run live predictions.")
        return

    model_info = fetch_model_info()
    if not model_info:
        st.error("❌ Backend not connected. Start it with: `uvicorn backend.api.main:app --reload`")
        return

    schema = model_info["raw_input_schema"]
    attack_label = st.selectbox(
        "Simulation profile", options=list(ATTACK_PROFILES.keys()), index=1
    )
    batch_size = st.slider("Batch size", min_value=1, max_value=25, value=1)
    explanation_top_k = st.slider(
        "Explanation depth", min_value=1, max_value=10, value=5
    )
    stream_cycles = st.slider("Stream iterations", min_value=3, max_value=30, value=8)

    metrics_row = st.columns(4)
    metrics_row[0].metric(
        "Recent Events", len(st.session_state.get("live_recent_events", []))
    )
    metrics_row[1].metric("Recent Alerts", len(st.session_state.get("live_alerts", [])))
    metrics_row[2].metric("Profile", attack_label)
    metrics_row[3].metric("Cadence", "2 sec")

    status_placeholder = st.empty()
    table_placeholder = st.empty()
    alerts_placeholder = st.empty()
    charts_placeholder = st.empty()

    if st.button("Run Simulation", use_container_width=True):
        logger.info(
            "Frontend live simulation requested.",
            extra={
                "event_type": "frontend_live_simulation",
                "details": {"profile": attack_label, "batch_size": batch_size},
            },
        )
        records = generate_live_records(
            schema=schema, attack_label=attack_label, count=batch_size
        )
        result, err = run_api_call(
            get_client().predict_records,
            records=records,
            include_explanations=True,
            explanation_top_k=explanation_top_k,
        )
        if err:
            render_api_error(err)
        else:
            st.session_state["latest_prediction_result"] = result
            append_live_events(result)
            logger.info(
                "Frontend simulation completed.",
                extra={
                    "event_type": "frontend_live_simulation_success",
                    "details": {"labels": result["summary"]["labels"]},
                },
            )
            st.success(
                f"Generated {result['summary']['prediction_count']} live predictions."
            )

    if st.button("Start Fake Live Feed", use_container_width=True):
        logger.info(
            "Frontend fake live feed started.",
            extra={
                "event_type": "frontend_live_feed_start",
                "details": {"profile": attack_label, "cycles": stream_cycles},
            },
        )
        status_placeholder.info("Streaming fake traffic to the classifier...")
        for step in range(stream_cycles):
            records = generate_live_records(
                schema=schema, attack_label=attack_label, count=batch_size
            )
            result, err = run_api_call(
                get_client().predict_records,
                records=records,
                include_explanations=True,
                explanation_top_k=explanation_top_k,
            )
            if err:
                render_api_error(err)
                status_placeholder.error(
                    "Live feed stopped because the API returned an error."
                )
                break

            st.session_state["latest_prediction_result"] = result
            append_live_events(result)
            if any(
                item.get("predicted_label") != "Normal"
                for item in result.get("predictions", [])
            ):
                logger.warning(
                    "Frontend live feed detected an attack.",
                    extra={
                        "event_type": "frontend_attack_detected",
                        "details": {
                            "labels": result["summary"]["labels"],
                            "tick": step + 1,
                        },
                    },
                )
            status_placeholder.success(
                f"Stream tick {step + 1}/{stream_cycles}: classified "
                f"{result['summary']['prediction_count']} event(s)."
            )
            render_live_dashboard(
                table_placeholder, alerts_placeholder, charts_placeholder
            )
            time.sleep(2)
        else:
            logger.info(
                "Frontend fake live feed completed.",
                extra={"event_type": "frontend_live_feed_complete"},
            )
            status_placeholder.success("Fake live feed completed.")

    render_live_dashboard(table_placeholder, alerts_placeholder, charts_placeholder)

    if st.session_state["latest_prediction_result"]:
        pred_df = pd.DataFrame(
            st.session_state["latest_prediction_result"]["predictions"]
        )
        if not pred_df.empty:
            st.markdown("**Latest API Response**")
            columns = [
                col
                for col in [
                    "row_index",
                    "predicted_label",
                    "confidence",
                    "recommendation_severity",
                    "recommendations",
                ]
                if col in pred_df.columns
            ]
            display_df = pred_df[columns].copy()
            if "recommendations" in display_df.columns:
                display_df["recommendations"] = display_df["recommendations"].map(
                    lambda items: (
                        " | ".join(items) if isinstance(items, list) else items
                    )
                )
            st.dataframe(display_df, use_container_width=True)


def render_statistics() -> None:
    st.subheader("Statistics")

    # ── Always show session deep-scan data ──────────────────────────────────
    scan_history = st.session_state.get("deep_scan_history", [])
    live_history = st.session_state.get("live_history", [])

    if not st.session_state.get("auth_token"):
        st.warning("🔒 Sign in from the **Login** tab for full statistics.")
        if scan_history or live_history:
            st.markdown("---")
            st.markdown("### 📊 Session Stats *(available without login)*")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Deep Scans", len(scan_history))
            c2.metric("ML Predictions", len(live_history))
            c3.metric("Vulns Found", st.session_state.get("total_vulns_found", 0))
            c4.metric("Critical Findings", st.session_state.get("total_critical_found", 0))
            if scan_history:
                st.dataframe(
                    pd.DataFrame(scan_history).rename(columns={
                        "target": "Target", "risk_grade": "Grade",
                        "score": "Risk Score", "vuln_count": "Vulns", "timestamp": "Time"
                    }),
                    use_container_width=True, hide_index=True
                )
        else:
            st.info("📭 No data yet. Run a Deep Scan from the sidebar, or use Live Predictions after signing in.")
        return

    result, err = run_api_call(get_client().stats)
    if err:
        render_api_error(err)
        return
    if result is None:
        st.error("Could not fetch statistics. Ensure the backend is running.")
        return

    # ── ML Metrics ───────────────────────────────────────────────────────────
    st.markdown("### 🤖 ML Prediction Metrics")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Predictions", result.get("total_predictions", 0))
    m2.metric("Total Uploads", result.get("total_uploads", 0))
    avg_conf = result.get("avg_confidence") or 0.0
    m3.metric("Avg Confidence", f"{float(avg_conf):.2%}")
    latest_ts = result.get("latest_prediction_at")
    m4.metric("Latest Prediction", str(latest_ts)[:19] if latest_ts else "N/A")

    # ── Deep Scan Metrics ─────────────────────────────────────────────────────
    st.markdown("### 🔍 Deep Security Scan Metrics")
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Deep Scans Run", len(scan_history))
    d2.metric("Vulnerabilities Found", st.session_state.get("total_vulns_found", 0))
    d3.metric("Critical Findings", st.session_state.get("total_critical_found", 0))
    avg_score = round(sum(h.get("score", 0) for h in scan_history) / max(len(scan_history), 1)) if scan_history else 0
    d4.metric("Avg Risk Score", f"{avg_score}/100")

    if scan_history:
        st.markdown("**Scan History**")
        hist_df = pd.DataFrame(scan_history)
        st.dataframe(
            hist_df.rename(columns={
                "target": "Target", "risk_grade": "Grade",
                "score": "Risk Score", "vuln_count": "Vulns", "timestamp": "Time"
            }),
            use_container_width=True, hide_index=True
        )

    # ── Alert Metrics ─────────────────────────────────────────────────────────
    st.markdown("### 🚨 Alert Metrics")
    a1, a2 = st.columns(2)
    a1.metric("Total Alerts", result.get("total_alerts", 0))
    a2.metric("Critical Threats", result.get("critical_threats", 0))

    # ── Attack Distribution ───────────────────────────────────────────────────
    labels = result.get("predictions_by_label", {})
    clean_labels = {
        k: v for k, v in labels.items()
        if v is not None and not (isinstance(v, float) and math.isnan(v)) and v > 0
    }

    if clean_labels:
        st.markdown("### 📊 Attack Type Distribution")
        col_pie, col_bar = st.columns(2)
        with col_pie:
            pie_df = pd.DataFrame({"label": list(clean_labels.keys()), "count": list(clean_labels.values())})
            colors = ["#38bdf8", "#fb7185", "#fbbf24", "#34d399", "#a78bfa",
                      "#f97316", "#e879f9", "#22d3ee"]
            fig, ax = plt.subplots(figsize=(5, 5))
            fig.patch.set_facecolor("#0f172a")
            ax.set_facecolor("#0f172a")
            wedges, texts, autotexts = ax.pie(
                pie_df["count"], labels=pie_df["label"],
                autopct="%1.1f%%", startangle=90,
                colors=colors[:len(pie_df)]
            )
            for t in texts + autotexts:
                t.set_color("#e2e8f0")
            ax.set_title("Attack Type Pie Chart", color="#e2e8f0")
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
        with col_bar:
            bar_df = pd.DataFrame(sorted(clean_labels.items(), key=lambda x: x[1], reverse=True),
                                  columns=["Attack Type", "Count"])
            st.markdown("**Count by Label**")
            st.dataframe(bar_df, use_container_width=True, hide_index=True)
    else:
        st.info("📭 No ML prediction data yet. Run some predictions from the **Live Predictions** or **Upload** tabs.")

    # ── Live Prediction Timeline ──────────────────────────────────────────────
    if live_history:
        st.markdown("### 📈 Live Prediction Timeline")
        hist_df = pd.DataFrame(live_history)
        hist_df["timestamp"] = pd.to_datetime(hist_df["timestamp"], errors="coerce")
        hist_df = hist_df.dropna(subset=["timestamp"])
        if not hist_df.empty:
            timeline = (
                hist_df.assign(minute=lambda df: df["timestamp"].dt.floor("min"))
                .groupby(["minute", "predicted_label"])
                .size()
                .unstack(fill_value=0)
                .sort_index()
            )
            if len(timeline) >= 2:
                st.line_chart(timeline)
            else:
                # Single time-bucket: use matplotlib bar chart with integer Y-axis
                colors_map = {"Normal": "#34d399", "BruteForce": "#38bdf8",
                              "DDoS": "#fb7185", "PortScan": "#fbbf24"}
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor("#0f172a")
                ax.set_facecolor("#111827")
                x_labels = [t.strftime("%H:%M") for t in timeline.index]
                bar_width = 0.25
                cols = list(timeline.columns)
                for i, col in enumerate(cols):
                    offset = (i - len(cols)/2 + 0.5) * bar_width
                    positions = [j + offset for j in range(len(x_labels))]
                    ax.bar(positions, timeline[col], width=bar_width,
                           label=col, color=colors_map.get(col, "#a78bfa"))
                ax.set_xticks(range(len(x_labels)))
                ax.set_xticklabels(x_labels, color="#e2e8f0")
                ax.yaxis.set_major_locator(MaxNLocator(integer=True))
                ax.set_ylabel("Count", color="#94a3b8")
                ax.set_title("Prediction Timeline", color="#e2e8f0", pad=10)
                ax.legend(facecolor="#1e293b", edgecolor="#334155", labelcolor="#e2e8f0")
                ax.tick_params(colors="#e2e8f0")
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                ax.spines["left"].set_color("#334155")
                ax.spines["bottom"].set_color("#334155")
                plt.tight_layout()
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)



def render_analytics() -> None:
    st.subheader("Analytics")
    st.caption("Operational rollups for attack mix and event trends.")

    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the **Login** tab to view full analytics.")
        # Show session-only scan chart even without login
        scan_history = st.session_state.get("deep_scan_history", [])
        if scan_history:
            st.markdown("**Session Deep Scan Risk Scores** *(no login required)*")
            df = pd.DataFrame(scan_history)
            if "score" in df.columns:
                chart_data = df.set_index("target")["score"]
                st.bar_chart(chart_data)
        return

    stats_result, err = run_api_call(get_client().stats)
    if err:
        render_api_error(err)
        return
    if stats_result is None:
        st.error("Could not fetch analytics. Ensure the backend is running.")
        return

    analytics = compute_analytics_payload(
        serialize_live_history(st.session_state.get("live_history", [])),
        stats_result,
    )

    top = st.columns(4)
    top[0].metric("Total Scans", analytics["total_scans"])
    top[1].metric("% Attacks", f"{analytics['percent_attacks']}%")
    top[2].metric("Top Attack Types", analytics["top_attack_summary"])
    latest_day = (
        analytics["daily_trend"]["day"].max().strftime("%Y-%m-%d")
        if not analytics["daily_trend"].empty else "N/A"
    )
    top[3].metric("Daily Trend", latest_day)

    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("**Attack Type Breakdown**")
        attack_counts = analytics["attack_counts"]
        if attack_counts.empty:
            st.info("Run predictions from **Live Predictions** or **Upload** tabs to populate this chart.")
        else:
            plot_df = attack_counts.head(10).sort_values(by="count", ascending=True)
            n_bars = len(plot_df)
            # Dynamic height: min 3 inches, 0.6 per bar, max 8
            bar_height = max(3.0, min(0.6 * n_bars, 8.0))
            # Scale bar thickness: thin for few bars, thicker for many
            bar_thickness = min(0.5, 0.3 * n_bars / max(n_bars, 1))
            if n_bars <= 2:
                bar_thickness = 0.15
            fig, ax = plt.subplots(figsize=(8, bar_height))
            fig.patch.set_facecolor("#0f172a")
            ax.set_facecolor("#111827")
            colors = ["#38bdf8" if row != "Normal" else "#34d399"
                      for row in plot_df["attack_type"]]
            bars = ax.barh(plot_df["attack_type"], plot_df["count"],
                           color=colors, height=bar_thickness)
            ax.bar_label(bars, fmt="%d", color="#e2e8f0", padding=3)
            ax.set_title("Top Attack Types", color="#e2e8f0", pad=10)
            ax.set_xlabel("Count", color="#94a3b8")
            ax.xaxis.set_major_locator(MaxNLocator(integer=True))
            # Add y-axis padding so bars don't fill the whole chart
            ax.set_ylim(-0.5, n_bars - 0.5)
            ax.tick_params(colors="#e2e8f0")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["left"].set_color("#334155")
            ax.spines["bottom"].set_color("#334155")
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)

    with chart_right:
        st.markdown("**Daily Event Trend**")
        daily_trend = analytics["daily_trend"]
        if daily_trend.empty:
            st.info("Daily trend appears once live or uploaded predictions accumulate.")
        else:
            trend_df = daily_trend.set_index("day")
            if len(trend_df) >= 2:
                st.line_chart(trend_df)
            else:
                # Single day: use matplotlib bar chart with integer Y-axis
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor("#0f172a")
                ax.set_facecolor("#111827")
                x_labels = [d.strftime("%a %d") for d in trend_df.index]
                bars = ax.bar(x_labels, trend_df["events"],
                              color="#38bdf8", width=0.4)
                ax.bar_label(bars, fmt="%d", color="#e2e8f0", padding=3)
                ax.yaxis.set_major_locator(MaxNLocator(integer=True))
                ax.set_ylabel("Events", color="#94a3b8")
                ax.set_title("Daily Event Trend", color="#e2e8f0", pad=10)
                ax.tick_params(colors="#e2e8f0")
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                ax.spines["left"].set_color("#334155")
                ax.spines["bottom"].set_color("#334155")
                plt.tight_layout()
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)

    if not analytics["events_df"].empty:
        st.markdown("**Recent Event Analytics Feed**")
        recent_df = (
            analytics["events_df"]
            .sort_values(by="timestamp", ascending=False)
            .head(25).copy()
        )
        recent_df["timestamp"] = recent_df["timestamp"].astype(str)
        st.dataframe(recent_df, use_container_width=True, hide_index=True)
    else:
        st.info("📭 No event feed yet. Run predictions to populate the analytics feed.")

    # ── Deep Scan Risk History ─────────────────────────────────────────────
    scan_history = st.session_state.get("deep_scan_history", [])
    if scan_history:
        st.markdown("---")
        st.markdown("### 🔍 Deep Scan Risk History")
        df = pd.DataFrame(scan_history)
        col_c, col_t = st.columns([1.5, 1])
        with col_c:
            if "score" in df.columns and len(df) > 0:
                grade_colors_map = {"A+": "#22c55e", "A": "#34d399", "B": "#38bdf8",
                                    "C": "#eab308", "D": "#f59e0b", "F": "#ef4444"}
                bar_colors = [grade_colors_map.get(g, "#38bdf8")
                              for g in df.get("risk_grade", ["B"] * len(df))]
                h = max(3.0, min(0.6 * len(df), 8.0))
                fig2, ax2 = plt.subplots(figsize=(8, h))
                fig2.patch.set_facecolor("#0f172a")
                ax2.set_facecolor("#111827")
                labels_short = df["target"].apply(lambda x: x[:25])
                bars2 = ax2.barh(labels_short, df["score"],
                                 color=bar_colors, height=0.5)
                ax2.bar_label(bars2, fmt="%d", color="#e2e8f0", padding=3)
                ax2.axvline(x=50, color="#ef4444", linestyle="--", alpha=0.4, label="Medium risk")
                ax2.set_title("Risk Score by Target (lower = safer)",
                              color="#e2e8f0", pad=10)
                ax2.set_xlabel("Risk Score (0–100)", color="#94a3b8")
                ax2.tick_params(colors="#e2e8f0")
                ax2.spines["top"].set_visible(False)
                ax2.spines["right"].set_visible(False)
                ax2.spines["left"].set_color("#334155")
                ax2.spines["bottom"].set_color("#334155")
                plt.tight_layout()
                st.pyplot(fig2, use_container_width=True)
                plt.close(fig2)
        with col_t:
            display = df[["target", "risk_grade", "score", "vuln_count"]].copy()
            display.columns = ["Target", "Grade", "Score", "Vulns"]
            st.dataframe(display, use_container_width=True, hide_index=True)



def render_explanations() -> None:
    st.subheader("Explainability")
    result = st.session_state.get("latest_prediction_result")
    if not result:
        st.info(
            "Run an upload prediction or live simulation first "
            "to populate explanations."
        )
        return

    summary = result.get("summary", {})
    importance = summary.get("global_feature_importance", [])
    if importance:
        imp_df = pd.DataFrame(importance).sort_values(
            by="mean_abs_shap", ascending=True
        )
        fig, ax = plt.subplots(figsize=(9, max(4, 0.4 * len(imp_df))))
        ax.barh(imp_df["feature"], imp_df["mean_abs_shap"], color="#38bdf8")
        ax.set_title("Global Feature Importance")
        ax.set_xlabel("Mean |SHAP value|")
        st.pyplot(fig, use_container_width=True)
        st.dataframe(
            pd.DataFrame(importance), use_container_width=True, hide_index=True
        )

    predictions = result.get("predictions", [])
    if predictions:
        row_options = [item["row_index"] for item in predictions]
        selected_row = st.selectbox("Inspect row", options=row_options, index=0)
        selected = next(
            item for item in predictions if item["row_index"] == selected_row
        )
        st.markdown(f"**Predicted label:** `{selected['predicted_label']}`")
        conf_raw = selected.get('confidence')
        if conf_raw is not None:
            try:
                conf_val = float(conf_raw)
                conf_display = f"{conf_val:.1%}" if conf_val <= 1.0 else f"{conf_val:.2f}"
            except (ValueError, TypeError):
                conf_display = str(conf_raw)
        else:
            conf_display = "N/A"
        st.markdown(f"**Confidence:** `{conf_display}`")
        if selected.get("recommendations"):
            st.markdown("**Recommendations**")
            for suggestion in selected.get("recommendations", []):
                st.write(f"- {suggestion}")

        if selected.get("class_probabilities"):
            prob_df = pd.DataFrame(
                {
                    "class_name": list(selected["class_probabilities"].keys()),
                    "probability": list(selected["class_probabilities"].values()),
                }
            ).sort_values(by="probability", ascending=True)
            fig, ax = plt.subplots(figsize=(8, max(3, 0.35 * len(prob_df))))
            ax.barh(prob_df["class_name"], prob_df["probability"], color="#f59e0b")
            ax.set_title("Class Probabilities")
            ax.set_xlim(0, 1)
            st.pyplot(fig, use_container_width=True)

        contributions = pd.DataFrame(selected.get("top_contributions", []))
        if not contributions.empty:
            st.markdown("**Top Local Contributions**")
            st.dataframe(contributions, use_container_width=True, hide_index=True)


def render_soc_dashboard() -> None:
    st.subheader("SOC Operations Dashboard")
    st.caption(
        "Real-time alert stream, network event feed, analyst notifications, and acknowledgement workflow."
    )

    api_base_url = st.session_state["api_base_url"]
    token = st.session_state.get("auth_token") or ""
    if not token:
        st.warning("🔒 Sign in from the **Login** tab to enable alert acknowledgement and secure analyst notifications.")

    st.info("ℹ️ The WebSocket feed connects live to the backend. If the backend is not running, **Demo Mode** activates automatically and simulates realistic SOC activity.")

    html = """
    <div style="font-family: 'Segoe UI', sans-serif; color: #e2e8f0; background:#0f172a; padding:18px; border-radius:18px;">
      <style>
        .soc-box { background:#111827; border:1px solid rgba(59,130,246,0.24); border-radius:14px; padding:14px; margin-bottom:12px; }
        .soc-title { font-size:1.1rem; font-weight:600; color:#38bdf8; margin-bottom:6px; }
        .soc-count { font-size:2rem; color:#f8fafc; font-weight:700; margin:4px 0; font-family: monospace; }
        .soc-label { color:#94a3b8; font-size:0.85rem; margin-bottom:8px; }
        .soc-list { list-style:none; padding:0; margin:0; }
        .soc-list li { border-bottom:1px solid rgba(148,163,184,0.12); padding:10px 0; font-size:0.88rem; }
        .soc-button { background:#2563eb; color:#fff; border:none; padding:6px 14px; border-radius:8px; cursor:pointer; font-size:0.82rem; }
        .soc-button:hover { background:#1d4ed8; }
        .soc-button.disabled { background:#475569; cursor:not-allowed; }
        .badge-critical { background:#fef2f2; color:#b91c1c; padding:2px 8px; border-radius:20px; font-size:0.75rem; font-weight:600; }
        .badge-high { background:#fff7ed; color:#c2410c; padding:2px 8px; border-radius:20px; font-size:0.75rem; font-weight:600; }
        .badge-medium { background:#fefce8; color:#854d0e; padding:2px 8px; border-radius:20px; font-size:0.75rem; font-weight:600; }
        .badge-info { background:#eff6ff; color:#1d4ed8; padding:2px 8px; border-radius:20px; font-size:0.75rem; }
        .status-connected { color:#22c55e; font-weight:700; }
        .status-disconnected { color:#f59e0b; font-weight:700; }
        .status-demo { color:#a78bfa; font-weight:700; }
        .demo-banner { background: rgba(167,139,250,0.08); border:1px solid rgba(167,139,250,0.3); border-radius:10px; padding:10px 14px; margin-bottom:12px; font-size:0.85rem; color:#a78bfa; }
      </style>

      <div class="soc-box">
        <div class="soc-title">🔌 Connection</div>
        <div class="soc-label">WebSocket channel:</div>
        <div id="ws-status" class="soc-count status-disconnected">Connecting…</div>
        <div id="demo-banner" class="demo-banner" style="display:none;">
          ⚡ <strong>Demo Mode Active</strong> — Backend not detected. Showing simulated SOC activity to demonstrate the interface.
        </div>
      </div>

      <div class="soc-box" id="metrics-panel">
        <div class="soc-title">📊 Operational Metrics</div>
        <div class="soc-label">Alerts, attack cadence, and event velocity updated live.</div>
        <div style="display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:12px;">
          <div style="background:#0f172a; border-radius:12px; padding:12px; text-align:center;">
            <div class="soc-label">Alerts</div>
            <div id="metric-alerts" class="soc-count" style="color:#fb7185;">0</div>
          </div>
          <div style="background:#0f172a; border-radius:12px; padding:12px; text-align:center;">
            <div class="soc-label">Detections</div>
            <div id="metric-detections" class="soc-count" style="color:#fbbf24;">0</div>
          </div>
          <div style="background:#0f172a; border-radius:12px; padding:12px; text-align:center;">
            <div class="soc-label">Notifications</div>
            <div id="metric-notifications" class="soc-count" style="color:#38bdf8;">0</div>
          </div>
          <div style="background:#0f172a; border-radius:12px; padding:12px; text-align:center;">
            <div class="soc-label">Logs</div>
            <div id="metric-logs" class="soc-count" style="color:#94a3b8;">0</div>
          </div>
        </div>
      </div>

      <div class="soc-box" id="timeline-panel">
        <div class="soc-title">⏱️ Alert Timeline</div>
        <ul id="timeline-list" class="soc-list"><li style="color:#475569;">No events yet…</li></ul>
      </div>

      <div class="soc-box" id="alert-panel">
        <div class="soc-title">🚨 Live Alert Feed</div>
        <ul id="alert-list" class="soc-list"><li style="color:#475569;">No alerts yet…</li></ul>
      </div>

      <div class="soc-box" id="notification-panel">
        <div class="soc-title">🔔 Notification Center</div>
        <ul id="notification-list" class="soc-list"><li style="color:#475569;">No notifications yet…</li></ul>
      </div>

      <div class="soc-box" id="log-panel">
        <div class="soc-title">📜 Streaming Logs</div>
        <ul id="log-list" class="soc-list"><li style="color:#475569;">No logs yet…</li></ul>
      </div>

      <audio id="alert-sound" src="data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAESsAACJWAAACABAAZGF0YSoAAAAA"></audio>
    </div>

    <script>
      const baseUrl = "{{API_BASE_URL}}";
      const token = "{{TOKEN}}";
      const wsUrl = baseUrl.replace(/^http/, "ws") + "/api/v1/ws/traffic";

      const alerts = [], timeline = [], notifications = [], logs = [];
      let alertCount = 0, detectionCount = 0, notificationCount = 0, logCount = 0;
      let demoMode = false, demoInterval = null;

      // ── Mock data for demo mode ──────────────────────────────────────────
      const DEMO_ALERTS = [
        { id: 1001, severity: "critical", description: "SQL Injection attempt from 185.220.101.45", alert_type: "WebAttack", src_ip: "185.220.101.45", timestamp: new Date().toISOString() },
        { id: 1002, severity: "high",     description: "SSH brute-force detected (47 attempts/min)", alert_type: "BruteForce", src_ip: "91.134.239.22", timestamp: new Date().toISOString() },
        { id: 1003, severity: "high",     description: "Port scan from unknown external host", alert_type: "PortScan", src_ip: "192.168.1.105", timestamp: new Date().toISOString() },
        { id: 1004, severity: "medium",   description: "Unusual outbound traffic volume detected", alert_type: "Anomaly", src_ip: "10.0.0.55", timestamp: new Date().toISOString() },
        { id: 1005, severity: "critical", description: "DDoS pattern: 8,000 packets/sec from botnet", alert_type: "DDoS", src_ip: "multiple", timestamp: new Date().toISOString() },
        { id: 1006, severity: "medium",   description: "Possible data exfiltration — 2.1 GB upload", alert_type: "Exfiltration", src_ip: "172.16.4.22", timestamp: new Date().toISOString() },
      ];
      const DEMO_LOGS = [
        { level: "warn",  message: "Model confidence below threshold: 0.52" },
        { level: "info",  message: "Prediction batch processed: 25 records" },
        { level: "error", message: "Backend WebSocket reconnect attempt #3" },
        { level: "info",  message: "Alert 1001 acknowledged by analyst" },
        { level: "warn",  message: "Rate limit approaching on /api/v1/predict" },
        { level: "info",  message: "Deep scan completed for target: 8.8.8.8" },
        { level: "debug", message: "Session heartbeat received" },
        { level: "warn",  message: "Suspicious HTTP header pattern blocked" },
      ];
      const DEMO_NOTIFS = [
        { level: "CRITICAL", message: "New critical alert requires immediate attention." },
        { level: "INFO",     message: "Scheduled scan completed — 3 new findings." },
        { level: "WARN",     message: "Auth failure spike: 12 failed logins in 60s." },
        { level: "INFO",     message: "ML model retrained with new traffic samples." },
      ];

      function ts() { return new Date().toLocaleTimeString(); }

      function badgeHtml(sev) {
        const cls = { critical:"badge-critical", high:"badge-high", medium:"badge-medium" }[sev] || "badge-info";
        return `<span class="${cls}">${(sev||"info").toUpperCase()}</span>`;
      }

      function renderState() {
        document.getElementById("metric-alerts").textContent       = alertCount;
        document.getElementById("metric-detections").textContent   = detectionCount;
        document.getElementById("metric-notifications").textContent = notificationCount;
        document.getElementById("metric-logs").textContent         = logCount;

        const alertList = document.getElementById("alert-list");
        if (alerts.length === 0) {
          alertList.innerHTML = '<li style="color:#475569;">No alerts yet…</li>';
        } else {
          alertList.innerHTML = alerts.slice(0,8).map(item => `
            <li>
              ${badgeHtml(item.severity)} <strong>${item.description}</strong><br/>
              <small style="color:#64748b;">${item.timestamp ? item.timestamp.substring(11,19) : ts()} &bull; ${item.alert_type||'Unknown'} &bull; ${item.src_ip||'—'}</small><br/>
              <button class="soc-button" style="margin-top:6px;" onclick="ackAlert(${item.id})">✓ Acknowledge</button>
            </li>
          `).join("");
        }

        const timelineList = document.getElementById("timeline-list");
        if (timeline.length === 0) {
          timelineList.innerHTML = '<li style="color:#475569;">No events yet…</li>';
        } else {
          timelineList.innerHTML = timeline.slice(0,8).map(item => `
            <li>${badgeHtml(item.type)} <strong>${item.summary}</strong><br/><small style="color:#64748b;">${item.timestamp}</small></li>
          `).join("");
        }

        const notificationList = document.getElementById("notification-list");
        if (notifications.length === 0) {
          notificationList.innerHTML = '<li style="color:#475569;">No notifications yet…</li>';
        } else {
          notificationList.innerHTML = notifications.slice(0,6).map(item => `
            <li>${badgeHtml((item.level||"info").toLowerCase())} ${item.message}<br/><small style="color:#64748b;">${item.timestamp||ts()}</small></li>
          `).join("");
        }

        const logList = document.getElementById("log-list");
        if (logs.length === 0) {
          logList.innerHTML = '<li style="color:#475569;">No logs yet…</li>';
        } else {
          logList.innerHTML = logs.slice(0,8).map(item => {
            const col = { error:"#fb7185", warn:"#fbbf24", info:"#38bdf8", debug:"#94a3b8" }[item.level] || "#94a3b8";
            return `<li><span style="color:${col};font-weight:600;">[${(item.level||"INFO").toUpperCase()}]</span> ${item.timestamp||ts()} &bull; ${item.message}</li>`;
          }).join("");
        }
      }

      function startDemoMode() {
        if (demoMode) return;
        demoMode = true;
        document.getElementById("ws-status").textContent = "Demo Mode";
        document.getElementById("ws-status").className   = "soc-count status-demo";
        document.getElementById("demo-banner").style.display = "block";

        // Pre-populate with a few items immediately
        const initAlerts = DEMO_ALERTS.slice(0,3);
        initAlerts.forEach(a => {
          alertCount++;
          alerts.unshift({ ...a, timestamp: ts() });
          timeline.unshift({ type: a.severity, summary: a.description, timestamp: ts() });
        });
        DEMO_NOTIFS.slice(0,2).forEach(n => {
          notificationCount++;
          notifications.unshift({ ...n, timestamp: ts() });
        });
        DEMO_LOGS.slice(0,3).forEach(l => {
          logCount++;
          logs.unshift({ ...l, timestamp: ts() });
        });
        renderState();

        // Simulate new events every 3 seconds
        let tick = 0;
        demoInterval = setInterval(() => {
          tick++;
          const pool = DEMO_ALERTS;
          const pick = pool[tick % pool.length];
          alertCount++;
          detectionCount++;
          const freshAlert = { ...pick, id: 2000+tick, timestamp: ts() };
          alerts.unshift(freshAlert);
          timeline.unshift({ type: pick.severity, summary: pick.description, timestamp: ts() });

          if (tick % 2 === 0) {
            notificationCount++;
            const n = DEMO_NOTIFS[tick % DEMO_NOTIFS.length];
            notifications.unshift({ ...n, timestamp: ts() });
          }
          logCount++;
          const l = DEMO_LOGS[tick % DEMO_LOGS.length];
          logs.unshift({ ...l, timestamp: ts() });

          // Cap lists
          if (alerts.length > 20)        alerts.splice(20);
          if (timeline.length > 20)      timeline.splice(20);
          if (notifications.length > 10) notifications.splice(10);
          if (logs.length > 20)          logs.splice(20);

          renderState();
        }, 3000);
      }

      async function ackAlert(alertId) {
        if (!token) { alert("Sign in to acknowledge alerts."); return; }
        try {
          await fetch(`${baseUrl}/api/v1/alerts/${alertId}/acknowledge`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
            body: JSON.stringify({ acknowledged_by: "analyst", comment: "Acknowledged via SOC dashboard" }),
          });
          timeline.unshift({ type: "info", summary: `Alert ${alertId} acknowledged`, timestamp: ts() });
          const idx = alerts.findIndex(a => a.id === alertId);
          if (idx > -1) alerts.splice(idx, 1);
          renderState();
        } catch (err) { console.error(err); }
      }

      // ── WebSocket connection ─────────────────────────────────────────────
      let connected = false;
      let demoTimeout = setTimeout(() => { if (!connected) startDemoMode(); }, 3000);

      try {
        const socket = new WebSocket(wsUrl);

        socket.addEventListener("open", () => {
          connected = true;
          clearTimeout(demoTimeout);
          document.getElementById("ws-status").textContent = "Connected";
          document.getElementById("ws-status").className   = "soc-count status-connected";
        });

        socket.addEventListener("close", () => {
          document.getElementById("ws-status").textContent = "Disconnected";
          document.getElementById("ws-status").className   = "soc-count status-disconnected";
          if (!demoMode) startDemoMode();
        });

        socket.addEventListener("error", () => {
          if (!connected && !demoMode) startDemoMode();
        });

        socket.addEventListener("message", event => {
          try {
            const message = JSON.parse(event.data);
            const payload  = message.payload || {};
            const ts_val   = payload.timestamp || ts();
            if (message.type === "alert") {
              alertCount++;
              timeline.unshift({ type: "alert", summary: payload.description, timestamp: ts_val });
              alerts.unshift(payload);
            }
            if (message.type === "traffic") {
              detectionCount++;
              timeline.unshift({ type: "traffic", summary: payload.description || "Traffic event", timestamp: ts_val });
            }
            if (message.type === "notification") {
              notificationCount++;
              notifications.unshift(payload);
            }
            if (message.type === "log") {
              logCount++;
              logs.unshift(payload);
            }
            if (message.type === "alert_ack") {
              timeline.unshift({ type: "info", summary: `Alert ${payload.id} acknowledged`, timestamp: ts_val });
            }
            renderState();
          } catch (err) { console.error(err); }
        });
      } catch(e) {
        if (!demoMode) startDemoMode();
      }

      renderState();
    </script>
    """
    html = html.replace("{{API_BASE_URL}}", api_base_url).replace("{{TOKEN}}", token)
    components.html(html, height=1100, scrolling=True)




def render_soc_assistant() -> None:
    st.subheader("SOC Analyst Assistant")
    st.caption(
        "Generate analyst-readable threat summaries, incident timelines, remediation guidance, and SHAP explanations via Groq AI."
    )

    if not st.session_state.get("auth_token"):
        st.warning("🔒 Please sign in from the **Login** tab to use the SOC Assistant.")
        return

    client = get_client()
    latest_result = st.session_state.get("latest_prediction_result")
    manual_source = "{}"
    if latest_result and latest_result.get("predictions"):
        first_prediction = latest_result["predictions"][0]
        manual_source = json.dumps(
            {
                "alert_id": None,
                "packet_metadata": {"source": "live_prediction"},
                "detection_result": first_prediction,
                "threat_intelligence": [],
                "shap_explanations": first_prediction.get("shap_values", {}),
                "historical_events": [],
                "system_metrics": {},
                "analyst_notes": "Use the latest prediction context to generate a concise incident briefing.",
            },
            indent=2,
        )

    input_json = st.text_area(
        "SOC context payload (JSON)",
        value=manual_source,
        height=280,
        help="Provide structured packet, detection, threat intelligence, SHAP and system context for the analyst assistant.",
    )

    if st.button("Run SOC Analysis", use_container_width=True):
        try:
            payload = json.loads(input_json)
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON payload: {exc}")
            return

        result, err = run_api_call(client.analyze_soc, payload)
        if err:
            render_api_error(err)
            return

        st.markdown("### Threat Summary")
        st.write(result.get("threat_summary", "No summary returned."))

        st.markdown("### Risk Assessment")
        st.write(result.get("risk_assessment", "No risk assessment returned."))

        st.markdown("### Remediation Recommendations")
        for suggestion in result.get("remediation_recommendations", []):
            st.write(f"- {suggestion}")

        st.markdown("### Incident Timeline")
        for event in result.get("incident_timeline", []):
            st.write(f"- {event.get('timestamp', 'unknown')}: {event.get('event', event)}")
            if event.get("detail"):
                st.caption(event["detail"])

        st.markdown("### False Positive Analysis")
        st.write(result.get("false_positive_analysis", "Not available."))

        st.markdown("### Correlated Events")
        for event in result.get("correlated_events", []):
            st.write(
                f"- {event.get('event_id', 'unnamed')}: {event.get('correlation_reason', event)}"
            )

        st.markdown("### SHAP Explanation")
        st.write(result.get("shap_explanation", "Not available."))

        st.markdown("### Incident Report")
        st.write(result.get("incident_report", "No incident report returned."))

        if result.get("raw_response"):
            with st.expander("Raw AI response"):
                st.json(result.get("raw_response"))


def render_about() -> None:
    st.subheader("About Safeguard-AI Lite")
    st.write("""
        Safeguard-AI Lite is an enterprise-grade intrusion-detection and security reconnaissance platform built around:
        - **FastAPI** — authenticated inference, REST, and WebSocket server
        - **scikit-learn / gradient-boosting** — ML intrusion classification
        - **SHAP** — explainability for every prediction
        - **SQLite** — lightweight operational telemetry and audit logs
        - **Streamlit** — analyst-facing dashboard with real-time feeds
        - **Groq AI (Llama 3.1)** — SOC analyst assistant and AI-powered deep scan intelligence
    """)

    st.markdown("---")
    st.markdown("### 🚀 How to Run")
    st.markdown("**Terminal 1 — Backend:**")
    st.code("uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000", language="bash")
    st.markdown("**Terminal 2 — Frontend:**")
    st.code("streamlit run frontend/App.py", language="bash")
    st.markdown("**First Login:**")
    st.write("Go to the **Login** tab → enter any username & password → click **Create Admin** → then **Sign In**.")

    st.markdown("---")
    st.markdown("### 📋 All Features")
    feature_data = {
        "Feature": ["🎯 Active Scanner", "🔍 Deep Security Scanner", "📡 Live Predictions",
                    "📤 Upload Dataset", "📊 Statistics", "📈 Analytics", "🧠 Explainability",
                    "🖥️ SOC Dashboard", "🤖 SOC Assistant", "📡 Live Monitor",
                    "🛡️ Security Center", "🎓 Beginner Guide"],
        "Where": ["Sidebar", "Sidebar", "Main tabs", "Main tabs", "Main tabs", "Main tabs",
                  "Main tabs", "Main tabs", "Main tabs", "Sidebar", "Sidebar", "Sidebar"],
        "Needs Login": ["Yes", "Yes", "Yes", "Yes", "Yes", "Yes", "No", "No", "Yes", "Yes", "Yes", "No"],
        "Description": [
            "Port scan, SSL, headers, WHOIS for any IP/domain",
            "Full AI-powered scan with risk score A+–F grade",
            "Simulate attacks, see AI classify in real-time",
            "Upload CSV logs, get bulk ML predictions",
            "Full stats: predictions, uploads, deep scans, alerts",
            "Charts: attack distribution, daily trends, risk history",
            "Per-prediction SHAP waterfall + class probabilities",
            "Real-time WebSocket alerts + demo mode when offline",
            "Groq AI incident briefings and remediation plans",
            "Live network capture control and alert feed",
            "Alert management with AI explanations",
            "Plain-English cybersecurity glossary",
        ]
    }
    st.dataframe(pd.DataFrame(feature_data), use_container_width=True, hide_index=True)



def main() -> None:
    init_state()
    apply_custom_css()
    render_sidebar()
    render_topbar()

    tabs = st.tabs(
        [
            "Login",
            "Home",
            "Upload",
            "Live Predictions",
            "Statistics",
            "Analytics",
            "Explanations",
            "SOC Dashboard",
            "SOC Assistant",
            "About",
        ]
    )
    with tabs[0]:
        render_login()
    with tabs[1]:
        render_home()
    with tabs[2]:
        render_upload()
    with tabs[3]:
        render_live_predictions()
    with tabs[4]:
        render_statistics()
    with tabs[5]:
        render_analytics()
    with tabs[6]:
        render_explanations()
    with tabs[7]:
        render_soc_dashboard()
    with tabs[8]:
        render_soc_assistant()
    with tabs[9]:
        render_about()


if __name__ == "__main__":
    main()
