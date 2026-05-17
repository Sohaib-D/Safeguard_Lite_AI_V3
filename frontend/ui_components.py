# frontend/ui_components.py
"""
Safeguard-AI Lite — UI Components & Design System.

Professional glassmorphic dark-mode design system with custom CSS,
reusable UI components, and Streamlit styling utilities.
"""

import streamlit as st
import pandas as pd
from typing import Any, Dict, List, Optional


def apply_custom_css():
    """
    Inject the complete Safeguard-AI Lite design system.
    Dramatically upgraded glassmorphic dark-mode theme with custom typography,
    animated backgrounds, and professional component styling.
    """
    st.markdown("""
        <style>
        /* ===================================================================
           GOOGLE FONTS IMPORT
           =================================================================== */
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        /* ===================================================================
           CSS CUSTOM PROPERTIES (DESIGN TOKENS)
           =================================================================== */
        :root {
            --bg-primary: #030712;
            --bg-secondary: #0c1220;
            --bg-tertiary: #111827;
            --bg-glass: rgba(15, 23, 42, 0.7);
            --bg-glass-strong: rgba(15, 23, 42, 0.85);
            --border-subtle: rgba(255, 255, 255, 0.06);
            --border-active: rgba(56, 189, 248, 0.4);
            --border-hover: rgba(56, 189, 248, 0.25);
            --accent-cyan: #38bdf8;
            --accent-cyan-glow: rgba(56, 189, 248, 0.15);
            --accent-cyan-deep: #0ea5e9;
            --accent-emerald: #34d399;
            --accent-emerald-glow: rgba(52, 211, 153, 0.15);
            --accent-amber: #fbbf24;
            --accent-amber-glow: rgba(251, 191, 36, 0.15);
            --accent-rose: #fb7185;
            --accent-rose-glow: rgba(251, 113, 133, 0.15);
            --accent-violet: #a78bfa;
            --accent-violet-glow: rgba(167, 139, 250, 0.15);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #475569;
            --text-inverse: #030712;
            --radius-sm: 8px;
            --radius-md: 14px;
            --radius-lg: 20px;
            --radius-xl: 28px;
            --shadow-glow: 0 0 30px rgba(56, 189, 248, 0.12);
            --shadow-glow-strong: 0 0 40px rgba(56, 189, 248, 0.2);
            --shadow-card: 0 4px 24px rgba(0, 0, 0, 0.4);
            --shadow-card-hover: 0 8px 40px rgba(0, 0, 0, 0.5);
            --shadow-inset: inset 0 1px 0 rgba(255, 255, 255, 0.04);
            --transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            --transition-fast: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            --transition-slow: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            --font-display: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
        }

        /* ===================================================================
           GLOBAL TYPOGRAPHY & RESET
           =================================================================== */
        html, body, [class*="css"] {
            font-family: var(--font-display) !important;
            color: var(--text-primary);
        }

        h1, h2, h3, h4, h5, h6,
        .stMarkdown h1, .stMarkdown h2, .stMarkdown h3,
        .stMarkdown h4, .stMarkdown h5, .stMarkdown h6 {
            font-family: var(--font-display) !important;
            font-weight: 600;
            letter-spacing: -0.02em;
            color: var(--text-primary) !important;
        }

        .stMarkdown h1 { font-size: 2rem !important; font-weight: 700; }
        .stMarkdown h2 { font-size: 1.5rem !important; font-weight: 600; }
        .stMarkdown h3 { font-size: 1.2rem !important; font-weight: 600; }

        p, span, div, li, label {
            font-family: var(--font-display) !important;
        }

        code, pre, .stCode, [data-testid="stCode"] {
            font-family: var(--font-mono) !important;
        }

        /* ===================================================================
           APP BACKGROUND — ANIMATED GRADIENT MESH
           =================================================================== */
        .stApp {
            background: var(--bg-primary) !important;
            position: relative;
        }

        .stApp::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
            background:
                radial-gradient(ellipse at 20% 20%, rgba(56, 189, 248, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(167, 139, 250, 0.04) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(52, 211, 153, 0.02) 0%, transparent 40%);
            background-attachment: fixed;
            animation: meshFloat 20s ease-in-out infinite alternate;
        }

        @keyframes meshFloat {
            0% {
                background:
                    radial-gradient(ellipse at 20% 20%, rgba(56, 189, 248, 0.06) 0%, transparent 50%),
                    radial-gradient(ellipse at 80% 80%, rgba(167, 139, 250, 0.04) 0%, transparent 50%),
                    radial-gradient(ellipse at 50% 50%, rgba(52, 211, 153, 0.02) 0%, transparent 40%);
            }
            100% {
                background:
                    radial-gradient(ellipse at 30% 30%, rgba(56, 189, 248, 0.05) 0%, transparent 50%),
                    radial-gradient(ellipse at 70% 70%, rgba(167, 139, 250, 0.05) 0%, transparent 50%),
                    radial-gradient(ellipse at 40% 60%, rgba(52, 211, 153, 0.03) 0%, transparent 40%);
            }
        }

        /* Ensure content is above the mesh */
        .stApp > * {
            position: relative;
            z-index: 1;
        }

        /* ===================================================================
           SIDEBAR DESIGN
           =================================================================== */
        [data-testid="stSidebar"] {
            background: rgba(12, 18, 32, 0.98) !important;
            border-right: 1px solid var(--border-subtle) !important;
            position: relative;
        }

        [data-testid="stSidebar"]::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 120px;
            background: linear-gradient(to top, rgba(3, 7, 18, 0.9), transparent);
            pointer-events: none;
            z-index: 10;
        }

        [data-testid="stSidebar"] [data-testid="stMarkdown"] {
            color: var(--text-secondary) !important;
        }

        [data-testid="stSidebar"] [data-testid="stMarkdown"]:hover {
            color: var(--text-primary) !important;
        }

        [data-testid="stSidebar"] .stButton > button {
            background: transparent !important;
            border: 1px solid var(--border-subtle) !important;
            border-left: 3px solid transparent !important;
            color: var(--text-secondary) !important;
            text-align: left !important;
            font-weight: 400 !important;
            border-radius: var(--radius-sm) !important;
            transition: var(--transition) !important;
            padding: 0.6rem 1rem !important;
        }

        [data-testid="stSidebar"] .stButton > button:hover {
            background: var(--accent-cyan-glow) !important;
            border-left-color: var(--accent-cyan) !important;
            border-color: var(--border-hover) !important;
            color: var(--text-primary) !important;
        }

        [data-testid="stSidebar"] hr {
            border-color: var(--border-subtle) !important;
            margin: 1rem 0 !important;
        }

        /* Sidebar navigation links */
        [data-testid="stSidebar"] a {
            color: var(--text-secondary) !important;
            text-decoration: none !important;
            transition: var(--transition-fast) !important;
        }

        [data-testid="stSidebar"] a:hover {
            color: var(--accent-cyan) !important;
        }

        /* ===================================================================
           STREAMLIT TABS — MODERN PILL DESIGN
           =================================================================== */
        .stTabs [data-baseweb="tab-list"] {
            background: transparent !important;
            border-bottom: 1px solid var(--border-subtle) !important;
            gap: 4px !important;
            padding: 0 !important;
        }

        .stTabs [data-baseweb="tab"] {
            background: transparent !important;
            border: none !important;
            border-bottom: 2px solid transparent !important;
            color: var(--text-secondary) !important;
            font-family: var(--font-display) !important;
            font-size: 0.85rem !important;
            font-weight: 500 !important;
            padding: 0.6rem 1.2rem !important;
            border-radius: var(--radius-sm) var(--radius-sm) 0 0 !important;
            transition: var(--transition) !important;
            white-space: nowrap !important;
        }

        .stTabs [data-baseweb="tab"]:hover {
            color: var(--text-primary) !important;
            background: var(--accent-cyan-glow) !important;
        }

        .stTabs [aria-selected="true"] {
            background: var(--accent-cyan-glow) !important;
            color: var(--accent-cyan) !important;
            border-bottom: 2px solid var(--accent-cyan) !important;
            font-weight: 600 !important;
        }

        .stTabs [data-baseweb="tab-panel"] {
            background: var(--bg-glass) !important;
            border: 1px solid var(--border-subtle) !important;
            border-top: none !important;
            border-radius: 0 0 var(--radius-md) var(--radius-md) !important;
            padding: 1.5rem !important;
            backdrop-filter: blur(8px) !important;
        }

        .stTabs [data-baseweb="tab-highlight"] {
            background-color: var(--accent-cyan) !important;
        }

        .stTabs [data-baseweb="tab-border"] {
            display: none !important;
        }

        /* ===================================================================
           METRIC CARDS
           =================================================================== */
        [data-testid="stMetric"] {
            background: var(--bg-tertiary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            padding: 1.25rem !important;
            transition: var(--transition) !important;
            box-shadow: var(--shadow-inset) !important;
        }

        [data-testid="stMetric"]:hover {
            border-color: var(--border-active) !important;
            box-shadow: var(--shadow-glow) !important;
            transform: translateY(-2px);
        }

        [data-testid="stMetric"] [data-testid="stMetricLabel"] {
            font-family: var(--font-display) !important;
            font-size: 0.75rem !important;
            font-weight: 500 !important;
            letter-spacing: 0.08em !important;
            text-transform: uppercase !important;
            color: var(--text-secondary) !important;
        }

        [data-testid="stMetric"] [data-testid="stMetricValue"] {
            font-family: var(--font-mono) !important;
            font-size: 1.6rem !important;
            font-weight: 500 !important;
            color: var(--text-primary) !important;
        }

        [data-testid="stMetric"] [data-testid="stMetricDelta"] {
            font-family: var(--font-mono) !important;
            font-size: 0.8rem !important;
        }

        /* ===================================================================
           DATAFRAME / TABLE STYLING
           =================================================================== */
        [data-testid="stDataFrame"] > div {
            border-radius: var(--radius-md) !important;
            border: 1px solid var(--border-subtle) !important;
            overflow: hidden !important;
            box-shadow: var(--shadow-card) !important;
        }

        [data-testid="stDataFrame"] [data-testid="glideDataEditor"] {
            border-radius: var(--radius-md) !important;
        }

        /* Table header styling */
        [data-testid="stDataFrame"] th,
        [data-testid="stDataFrame"] .gdg-header-cell {
            background: var(--bg-secondary) !important;
            color: var(--text-secondary) !important;
            font-family: var(--font-mono) !important;
            font-size: 0.7rem !important;
            font-weight: 500 !important;
            letter-spacing: 0.1em !important;
            text-transform: uppercase !important;
            border-bottom: 1px solid var(--border-subtle) !important;
        }

        /* Table rows */
        [data-testid="stDataFrame"] td,
        [data-testid="stDataFrame"] .gdg-cell {
            font-family: var(--font-display) !important;
            font-size: 0.82rem !important;
            color: var(--text-primary) !important;
            border-bottom: 1px solid var(--border-subtle) !important;
        }

        [data-testid="stDataFrame"] tr:nth-child(even) {
            background: rgba(17, 24, 39, 0.3) !important;
        }

        [data-testid="stDataFrame"] tr:hover {
            background: var(--accent-cyan-glow) !important;
        }

        /* ===================================================================
           BUTTONS
           =================================================================== */
        /* Primary button */
        .stButton > button[kind="primary"],
        .stButton > button[data-testid="baseButton-primary"] {
            background: linear-gradient(135deg, #0ea5e9, #6366f1) !important;
            color: white !important;
            border: none !important;
            border-radius: var(--radius-sm) !important;
            font-family: var(--font-display) !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
            letter-spacing: 0.02em !important;
            padding: 0.65rem 1.5rem !important;
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3) !important;
            transition: var(--transition) !important;
            text-transform: none !important;
        }

        .stButton > button[kind="primary"]:hover,
        .stButton > button[data-testid="baseButton-primary"]:hover {
            transform: scale(1.02) !important;
            filter: brightness(1.1) !important;
            box-shadow: 0 0 30px rgba(56, 189, 248, 0.45) !important;
        }

        .stButton > button[kind="primary"]:active,
        .stButton > button[data-testid="baseButton-primary"]:active {
            transform: scale(0.98) !important;
        }

        /* Secondary / default buttons */
        .stButton > button {
            background: transparent !important;
            color: var(--accent-cyan) !important;
            border: 1px solid var(--border-hover) !important;
            border-radius: var(--radius-sm) !important;
            font-family: var(--font-display) !important;
            font-weight: 500 !important;
            font-size: 0.82rem !important;
            padding: 0.6rem 1.2rem !important;
            transition: var(--transition) !important;
        }

        .stButton > button:hover {
            background: var(--accent-cyan-glow) !important;
            border-color: var(--accent-cyan) !important;
            color: var(--text-primary) !important;
            box-shadow: var(--shadow-glow) !important;
        }

        .stButton > button:active {
            transform: scale(0.97) !important;
        }

        /* Download button */
        .stDownloadButton > button {
            background: linear-gradient(135deg, rgba(52, 211, 153, 0.1), rgba(52, 211, 153, 0.05)) !important;
            border: 1px solid rgba(52, 211, 153, 0.3) !important;
            color: var(--accent-emerald) !important;
            border-radius: var(--radius-sm) !important;
            font-family: var(--font-display) !important;
            font-weight: 500 !important;
            transition: var(--transition) !important;
        }

        .stDownloadButton > button:hover {
            background: rgba(52, 211, 153, 0.15) !important;
            border-color: var(--accent-emerald) !important;
            box-shadow: 0 0 20px rgba(52, 211, 153, 0.2) !important;
        }

        /* ===================================================================
           EXPANDERS — GLASSMORPHISM
           =================================================================== */
        .streamlit-expanderHeader {
            background: var(--bg-glass) !important;
            backdrop-filter: blur(12px) !important;
            -webkit-backdrop-filter: blur(12px) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
            font-weight: 500 !important;
            transition: var(--transition) !important;
            padding: 0.8rem 1.2rem !important;
        }

        .streamlit-expanderHeader:hover {
            border-color: var(--border-hover) !important;
            background: var(--bg-glass-strong) !important;
        }

        .streamlit-expanderHeader svg {
            color: var(--accent-cyan) !important;
        }

        [data-testid="stExpander"] {
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            overflow: hidden !important;
            background: var(--bg-glass) !important;
            backdrop-filter: blur(12px) !important;
        }

        [data-testid="stExpander"] details {
            border: none !important;
        }

        [data-testid="stExpander"] summary {
            background: var(--bg-glass) !important;
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
            font-weight: 500 !important;
            padding: 0.8rem 1.2rem !important;
            border-radius: var(--radius-md) !important;
            transition: var(--transition) !important;
        }

        [data-testid="stExpander"] summary:hover {
            background: var(--bg-glass-strong) !important;
        }

        [data-testid="stExpander"] summary svg {
            color: var(--accent-cyan) !important;
        }

        [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
            background: rgba(12, 18, 32, 0.5) !important;
            padding: 1.2rem !important;
        }

        /* ===================================================================
           TEXT INPUTS & SELECT BOXES
           =================================================================== */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea,
        .stNumberInput > div > div > input {
            background: var(--bg-secondary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-sm) !important;
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
            font-size: 0.9rem !important;
            padding: 0.7rem 1rem !important;
            transition: var(--transition) !important;
            caret-color: var(--accent-cyan) !important;
        }

        .stTextInput > div > div > input:focus,
        .stTextArea > div > div > textarea:focus,
        .stNumberInput > div > div > input:focus {
            border-color: var(--border-active) !important;
            box-shadow: 0 0 0 3px var(--accent-cyan-glow), var(--shadow-glow) !important;
            outline: none !important;
        }

        .stTextInput > div > div > input::placeholder,
        .stTextArea > div > div > textarea::placeholder {
            color: var(--text-muted) !important;
            opacity: 0.7 !important;
        }

        /* Select boxes */
        .stSelectbox > div > div,
        .stMultiSelect > div > div {
            background: var(--bg-secondary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-sm) !important;
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
            transition: var(--transition) !important;
        }

        .stSelectbox > div > div:focus-within,
        .stMultiSelect > div > div:focus-within {
            border-color: var(--border-active) !important;
            box-shadow: 0 0 0 3px var(--accent-cyan-glow) !important;
        }

        [data-baseweb="select"] {
            background: var(--bg-secondary) !important;
        }

        [data-baseweb="select"] > div {
            background: var(--bg-secondary) !important;
            border-color: var(--border-subtle) !important;
        }

        /* Dropdown menu */
        [data-baseweb="menu"],
        [data-baseweb="popover"] > div {
            background: var(--bg-tertiary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-sm) !important;
            box-shadow: var(--shadow-card) !important;
        }

        [data-baseweb="menu"] li {
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
        }

        [data-baseweb="menu"] li:hover {
            background: var(--accent-cyan-glow) !important;
        }

        /* ===================================================================
           CODE BLOCKS
           =================================================================== */
        .stCode, [data-testid="stCode"],
        pre, .stCodeBlock {
            background: var(--bg-secondary) !important;
            font-family: var(--font-mono) !important;
            font-size: 0.8rem !important;
            border: 1px solid var(--border-subtle) !important;
            border-left: 3px solid var(--accent-violet) !important;
            border-radius: var(--radius-sm) !important;
            color: var(--text-primary) !important;
            padding: 1rem !important;
        }

        code {
            font-family: var(--font-mono) !important;
            background: var(--bg-secondary) !important;
            color: var(--accent-cyan) !important;
            padding: 0.15em 0.4em !important;
            border-radius: 4px !important;
            font-size: 0.82em !important;
        }

        /* ===================================================================
           ALERTS & CALLOUTS
           =================================================================== */
        [data-testid="stAlert"] {
            border-radius: var(--radius-md) !important;
            backdrop-filter: blur(8px) !important;
            font-family: var(--font-display) !important;
        }

        /* Success */
        .stSuccess, [data-baseweb="notification"][kind="positive"],
        .element-container .stAlert[data-baseweb="notification"][kind="positive"] {
            background: rgba(52, 211, 153, 0.06) !important;
            border: 1px solid rgba(52, 211, 153, 0.15) !important;
            border-left: 4px solid var(--accent-emerald) !important;
            border-radius: var(--radius-md) !important;
            color: var(--accent-emerald) !important;
        }

        /* Warning */
        .stWarning, [data-baseweb="notification"][kind="warning"] {
            background: rgba(251, 191, 36, 0.06) !important;
            border: 1px solid rgba(251, 191, 36, 0.15) !important;
            border-left: 4px solid var(--accent-amber) !important;
            border-radius: var(--radius-md) !important;
            color: var(--accent-amber) !important;
        }

        /* Error */
        .stError, [data-baseweb="notification"][kind="negative"] {
            background: rgba(251, 113, 133, 0.06) !important;
            border: 1px solid rgba(251, 113, 133, 0.15) !important;
            border-left: 4px solid var(--accent-rose) !important;
            border-radius: var(--radius-md) !important;
            color: var(--accent-rose) !important;
        }

        /* Info */
        .stInfo, [data-baseweb="notification"][kind="info"] {
            background: rgba(56, 189, 248, 0.06) !important;
            border: 1px solid rgba(56, 189, 248, 0.15) !important;
            border-left: 4px solid var(--accent-cyan) !important;
            border-radius: var(--radius-md) !important;
            color: var(--accent-cyan) !important;
        }

        /* Fix alert text color for Streamlit's built-in alerts */
        .stAlert > div {
            color: var(--text-primary) !important;
        }

        div[data-testid="stNotification"] {
            border-radius: var(--radius-md) !important;
            font-family: var(--font-display) !important;
        }

        /* ===================================================================
           PROGRESS BARS
           =================================================================== */
        .stProgress > div > div > div {
            background: var(--bg-secondary) !important;
            border-radius: 4px !important;
        }

        .stProgress > div > div > div > div {
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-violet)) !important;
            border-radius: 4px !important;
        }

        /* ===================================================================
           SPINNER
           =================================================================== */
        .stSpinner > div {
            border-color: var(--accent-cyan) !important;
        }

        /* ===================================================================
           CHECKBOX, RADIO, TOGGLE
           =================================================================== */
        .stCheckbox label span,
        .stRadio label span {
            color: var(--text-primary) !important;
            font-family: var(--font-display) !important;
        }

        /* ===================================================================
           FILE UPLOADER
           =================================================================== */
        [data-testid="stFileUploader"] {
            background: var(--bg-secondary) !important;
            border: 2px dashed var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            padding: 2rem !important;
            transition: var(--transition) !important;
        }

        [data-testid="stFileUploader"]:hover {
            border-color: var(--border-active) !important;
            background: var(--accent-cyan-glow) !important;
        }

        /* ===================================================================
           DIVIDERS
           =================================================================== */
        hr, .stMarkdown hr {
            border: none !important;
            border-top: 1px solid var(--border-subtle) !important;
            margin: 2rem 0 !important;
        }

        /* ===================================================================
           JSON VIEWER
           =================================================================== */
        [data-testid="stJson"] {
            background: var(--bg-secondary) !important;
            border: 1px solid var(--border-subtle) !important;
            border-radius: var(--radius-md) !important;
            padding: 1rem !important;
            font-family: var(--font-mono) !important;
        }

        /* ===================================================================
           SCROLLBARS
           =================================================================== */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--text-muted);
            border-radius: 3px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }

        /* ===================================================================
           MAIN CONTENT AREA PADDING
           =================================================================== */
        .main .block-container {
            padding-top: 2rem !important;
            padding-bottom: 2rem !important;
            max-width: 1400px !important;
        }

        /* ===================================================================
           HIDE STREAMLIT DEFAULTS
           =================================================================== */
        #MainMenu { visibility: hidden; }
        footer { visibility: hidden; }
        header[data-testid="stHeader"] {
            background: transparent !important;
        }

        /* ===================================================================
           TOOLTIP
           =================================================================== */
        [data-testid="stTooltipIcon"] {
            color: var(--text-muted) !important;
        }

        /* ===================================================================
           CUSTOM UTILITY CLASSES
           =================================================================== */
        
        /* Security Card — Glass card with hover glow */
        .security-card {
            background: var(--bg-glass);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 1.5rem;
            transition: var(--transition);
            box-shadow: var(--shadow-inset);
        }

        .security-card:hover {
            border-color: var(--border-active);
            box-shadow: var(--shadow-glow), var(--shadow-card);
            transform: translateY(-2px);
        }

        /* Severity Badges */
        .severity-critical {
            display: inline-block;
            background: var(--accent-rose-glow);
            border: 1px solid rgba(251, 113, 133, 0.3);
            color: var(--accent-rose);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            font-family: var(--font-display);
        }

        .severity-high {
            display: inline-block;
            background: var(--accent-amber-glow);
            border: 1px solid rgba(251, 191, 36, 0.3);
            color: var(--accent-amber);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            font-family: var(--font-display);
        }

        .severity-medium {
            display: inline-block;
            background: var(--accent-cyan-glow);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: var(--accent-cyan);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            font-family: var(--font-display);
        }

        .severity-low {
            display: inline-block;
            background: var(--accent-emerald-glow);
            border: 1px solid rgba(52, 211, 153, 0.3);
            color: var(--accent-emerald);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            font-family: var(--font-display);
        }

        /* Risk Grade Badges */
        .risk-grade-a {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: var(--accent-emerald-glow);
            border: 3px solid var(--accent-emerald);
            color: var(--accent-emerald);
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            box-shadow: 0 0 20px rgba(52, 211, 153, 0.2);
        }

        .risk-grade-b {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: var(--accent-cyan-glow);
            border: 3px solid var(--accent-cyan);
            color: var(--accent-cyan);
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.2);
        }

        .risk-grade-c {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: var(--accent-amber-glow);
            border: 3px solid var(--accent-amber);
            color: var(--accent-amber);
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.2);
        }

        .risk-grade-d {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: rgba(245, 158, 11, 0.15);
            border: 3px solid #f59e0b;
            color: #f59e0b;
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.2);
        }

        .risk-grade-f {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: var(--accent-rose-glow);
            border: 3px solid var(--accent-rose);
            color: var(--accent-rose);
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            box-shadow: 0 0 20px rgba(251, 113, 133, 0.2);
        }

        /* Scan Terminal */
        .scan-terminal {
            background: #0a0e14;
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 1.2rem 1.5rem;
            font-family: var(--font-mono);
            font-size: 0.8rem;
            color: #4ade80;
            line-height: 1.8;
            overflow-x: auto;
            box-shadow: var(--shadow-card);
        }

        .scan-terminal .prompt {
            color: var(--accent-cyan);
        }

        .scan-terminal .success {
            color: #4ade80;
        }

        .scan-terminal .error {
            color: var(--accent-rose);
        }

        .scan-terminal .info {
            color: var(--text-secondary);
        }

        /* Metric Strip */
        .metric-strip {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 1.5rem 0;
        }

        .metric-strip-item {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 1.2rem;
            text-align: center;
            transition: var(--transition);
        }

        .metric-strip-item:hover {
            border-color: var(--border-active);
            box-shadow: var(--shadow-glow);
        }

        .metric-strip-value {
            font-family: var(--font-mono);
            font-size: 1.5rem;
            font-weight: 500;
            color: var(--accent-cyan);
            display: block;
            margin-bottom: 4px;
        }

        .metric-strip-label {
            font-size: 0.7rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--text-muted);
        }

        /* Vulnerability Card */
        .vuln-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 1.2rem 1.5rem;
            margin-bottom: 12px;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }

        .vuln-card::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
        }

        .vuln-card.vuln-critical::before { background: var(--accent-rose); }
        .vuln-card.vuln-high::before { background: var(--accent-amber); }
        .vuln-card.vuln-medium::before { background: var(--accent-cyan); }
        .vuln-card.vuln-low::before { background: var(--accent-emerald); }

        .vuln-card:hover {
            border-color: var(--border-hover);
            box-shadow: var(--shadow-card);
            transform: translateX(2px);
        }

        .vuln-card-title {
            font-weight: 600;
            font-size: 0.9rem;
            color: var(--text-primary);
            margin-bottom: 6px;
        }

        .vuln-card-desc {
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }

        /* Remediation Item */
        .remediation-item {
            display: flex;
            align-items: flex-start;
            gap: 14px;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border-subtle);
        }

        .remediation-item:last-child {
            border-bottom: none;
        }

        .remediation-number {
            width: 28px;
            height: 28px;
            min-width: 28px;
            border-radius: 50%;
            background: var(--accent-cyan-glow);
            border: 1px solid rgba(56, 189, 248, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 600;
            color: var(--accent-cyan);
        }

        .remediation-content {
            flex: 1;
        }

        .remediation-action {
            font-size: 0.85rem;
            color: var(--text-primary);
            margin-bottom: 8px;
            line-height: 1.4;
        }

        .remediation-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .remediation-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.65rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }

        .remediation-badge.effort-low { background: rgba(52, 211, 153, 0.1); color: var(--accent-emerald); }
        .remediation-badge.effort-medium { background: rgba(251, 191, 36, 0.1); color: var(--accent-amber); }
        .remediation-badge.effort-high { background: rgba(251, 113, 133, 0.1); color: var(--accent-rose); }
        .remediation-badge.impact-critical { background: rgba(251, 113, 133, 0.1); color: var(--accent-rose); }
        .remediation-badge.impact-high { background: rgba(251, 191, 36, 0.1); color: var(--accent-amber); }
        .remediation-badge.impact-medium { background: rgba(56, 189, 248, 0.1); color: var(--accent-cyan); }

        /* ===================================================================
           RESPONSIVE ADJUSTMENTS
           =================================================================== */
        @media (max-width: 768px) {
            .metric-strip {
                grid-template-columns: repeat(2, 1fr);
            }

            .main .block-container {
                padding-left: 1rem !important;
                padding-right: 1rem !important;
            }
        }

        @media (max-width: 480px) {
            .metric-strip {
                grid-template-columns: 1fr;
            }
        }

        /* ===================================================================
           ANIMATION UTILITIES
           =================================================================== */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideInLeft {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        @keyframes glowPulse {
            0%, 100% { box-shadow: 0 0 15px rgba(56, 189, 248, 0.2); }
            50% { box-shadow: 0 0 30px rgba(56, 189, 248, 0.4); }
        }

        .animate-fadeIn { animation: fadeIn 0.4s ease-out; }
        .animate-slideIn { animation: slideInLeft 0.3s ease-out; }
        .animate-pulse { animation: pulse 2s ease-in-out infinite; }
        .animate-glow { animation: glowPulse 2s ease-in-out infinite; }

        /* ===================================================================
           HIDE STREAMLIT TOP CHROME (header, deploy button, toolbar)
           =================================================================== */
        [data-testid="stHeader"]          { display: none !important; }
        [data-testid="stToolbar"]         { display: none !important; }
        [data-testid="stAppDeployButton"] { display: none !important; }
        [data-testid="stMainMenuButton"]  { display: none !important; }
        [data-testid="stDecoration"]      { display: none !important; }
        .stAppHeader                      { display: none !important; }

        /* Remove blank space left behind by the hidden header */
        .main .block-container {
            padding-top: 0.75rem !important;
            margin-top: 0 !important;
        }
        /* ── Sidebar: reduce top gap (GLOBAL) ─────────── */
        section[data-testid="stSidebar"] > div:first-child {
            padding-top: 0.2rem !important;
        }
        section[data-testid="stSidebar"] [data-testid="stSidebarNav"] {
            padding-top: 0 !important;
            margin-top: 0 !important;
        }
        /* Reduce the Streamlit sidebar header (close btn area) */
        [data-testid="stSidebarHeader"] {
            padding: 0.3rem 0.5rem !important;
            min-height: unset !important;
        }
        /* ── Sidebar collapse arrow → ☰ hamburger (GLOBAL) ─
           Streamlit 1.39: data-testid="stBaseButton-headerNoPadding"
           Double-escape for Python: \\2630 → CSS \2630 → ☰ ───────── */
        button[data-testid="stBaseButton-headerNoPadding"] {
            color: transparent !important;
            overflow: hidden !important;
        }
        button[data-testid="stBaseButton-headerNoPadding"] svg {
            display: none !important;
        }
        button[data-testid="stBaseButton-headerNoPadding"]::after {
            content: '\\2630' !important;
            font-size: 1.3rem !important;
            color: #38bdf8 !important;
            line-height: 1 !important;
        }
        /* Close button (inside sidebar) → ✕ */
        section[data-testid="stSidebar"] button[data-testid="stBaseButton-headerNoPadding"]::after {
            content: '\\2715' !important;
            font-size: 1.1rem !important;
            color: #94a3b8 !important;
        }
        /* ── Main content: reduce top gap ─────────────────── */
        [data-testid="stMainBlockContainer"] {
            padding-top: 1.5rem !important;
        }

        /* ═══════════════════════════════════════════════════
           MOBILE RESPONSIVENESS — screens up to 768px wide
           ═══════════════════════════════════════════════════ */

        @media screen and (max-width: 768px) {

          /* ── Layout & Spacing ─────────────────────────── */
          .main .block-container {
              padding: 0.5rem 0.6rem 2rem !important;
              max-width: 100vw !important;
              overflow-x: hidden !important;
          }

          /* ── GLOBAL TEXT CONTAINMENT ─────────────────── */
          .main .block-container * {
              max-width: 100% !important;
              box-sizing: border-box !important;
          }
          .stMarkdown, .stMarkdown p, .stMarkdown li,
          .stMarkdown span, .stMarkdown div,
          [data-testid="stCaptionContainer"],
          [data-testid="stAlert"] div,
          [data-testid="stAlert"] p {
              word-wrap: break-word !important;
              overflow-wrap: break-word !important;
              word-break: break-word !important;
              white-space: normal !important;
              max-width: 100% !important;
          }

          /* Inline code tags (like /predict) must not overflow */
          .stMarkdown code, p code, li code,
          [data-testid="stAlert"] code {
              word-break: break-all !important;
              white-space: pre-wrap !important;
              font-size: 0.78rem !important;
          }

          /* ── Sidebar: collapse arrow → hamburger ☰ ───── */
          [data-testid="collapsedControl"] {
              top: 0.3rem !important;
          }
          [data-testid="collapsedControl"] svg {
              display: none !important;
          }
          [data-testid="collapsedControl"] button::before {
              content: '☰' !important;
              font-size: 1.4rem !important;
              color: var(--accent-cyan) !important;
              display: flex !important;
              align-items: center !important;
              justify-content: center !important;
          }

          /* ── Sidebar: remove top gap ────────────────── */
          section[data-testid="stSidebar"] {
              width: 80vw !important;
              min-width: unset !important;
              max-width: 320px !important;
          }
          section[data-testid="stSidebar"] > div:first-child {
              padding-top: 0.3rem !important;
          }
          section[data-testid="stSidebar"][aria-expanded="true"] {
              transform: translateX(0) !important;
          }
          section[data-testid="stSidebar"][aria-expanded="false"] {
              transform: translateX(-100%) !important;
          }
          /* Close button inside sidebar: also hamburger style */
          section[data-testid="stSidebar"] button[kind="header"] svg {
              display: none !important;
          }
          section[data-testid="stSidebar"] button[kind="header"]::before {
              content: '✕' !important;
              font-size: 1.2rem !important;
              color: var(--text-secondary) !important;
          }

          /* ── Tabs: horizontal scroll on overflow ──────── */
          [data-testid="stTabs"] > div:first-child {
              overflow-x: auto !important;
              white-space: nowrap !important;
              -webkit-overflow-scrolling: touch !important;
              scrollbar-width: none !important;
          }
          [data-testid="stTabs"] > div:first-child::-webkit-scrollbar {
              display: none !important;
          }
          [data-testid="stTabsTab"] {
              font-size: 0.75rem !important;
              padding: 0.4rem 0.6rem !important;
              min-width: max-content !important;
          }

          /* ── st.columns → single column stack ────────── */
          [data-testid="stHorizontalBlock"] {
              flex-direction: column !important;
              gap: 0.75rem !important;
          }
          [data-testid="stHorizontalBlock"] > div {
              width: 100% !important;
              min-width: unset !important;
              flex: 1 1 100% !important;
          }

          /* ── Metrics: 2-column grid instead of 4 ─────── */
          [data-testid="stMetric"] {
              min-width: 45% !important;
          }

          /* ── Typography scaling ───────────────────────── */
          h1 { font-size: 1.3rem !important; }
          h2 { font-size: 1.1rem !important; }
          h3 { font-size: 1rem !important; }
          p, li, label {
              font-size: 0.84rem !important;
              line-height: 1.5 !important;
          }
          /* Less important text: smaller */
          .stCaption, [data-testid="stCaptionContainer"],
          .section-label, .hero-subtitle,
          [data-testid="stMarkdownContainer"] small {
              font-size: 0.72rem !important;
              color: var(--text-secondary) !important;
          }

          /* ── Buttons: full width + touch-safe height ──── */
          [data-testid="stButton"] > button {
              width: 100% !important;
              min-height: 48px !important;
              font-size: 0.88rem !important;
              border-radius: 10px !important;
          }

          /* ── Input fields: larger touch targets ──────── */
          input[type="text"],
          input[type="password"],
          input[type="email"],
          textarea,
          [data-testid="stTextInput"] input,
          [data-testid="stTextArea"] textarea {
              min-height: 48px !important;
              font-size: 1rem !important;
              border-radius: 10px !important;
              padding: 0.6rem 0.9rem !important;
              -webkit-appearance: none !important;
          }

          /* ── Select boxes / dropdowns ─────────────────── */
          select,
          [data-testid="stSelectbox"] select {
              font-size: 1rem !important;
              min-height: 48px !important;
          }

          /* ── DataFrames: horizontal scroll ───────────── */
          [data-testid="stDataFrame"],
          [data-testid="stTable"],
          .stDataFrame {
              overflow-x: auto !important;
              -webkit-overflow-scrolling: touch !important;
              max-width: 100% !important;
          }
          [data-testid="stDataFrame"] > div {
              min-width: 400px !important;
          }

          /* ── Charts / pyplot images ───────────────────── */
          [data-testid="stImage"] img,
          .stPyplot img {
              max-width: 100% !important;
              height: auto !important;
          }

          /* ── Expanders ────────────────────────────────── */
          [data-testid="stExpander"] {
              border-radius: 10px !important;
          }
          [data-testid="stExpander"] summary {
              font-size: 0.88rem !important;
              padding: 0.5rem !important;
          }

          /* ── Code blocks ──────────────────────────────── */
          pre, code {
              font-size: 0.72rem !important;
              overflow-x: auto !important;
              white-space: pre-wrap !important;
              word-break: break-all !important;
          }

          /* ── Top-right auth badge: smaller on mobile ──── */
          div[style*="position:fixed"][style*="right:1.2rem"] {
              top: 0.3rem !important;
              right: 0.5rem !important;
              font-size: 0.62rem !important;
              padding: 0.18rem 0.5rem !important;
              max-width: 50vw !important;
              overflow: hidden !important;
              text-overflow: ellipsis !important;
              white-space: nowrap !important;
          }

          /* ── Hero / banner cards ──────────────────────── */
          .hero-card, .hero-banner {
              padding: 0.85rem !important;
              border-radius: 12px !important;
          }
          .hero-card h2, .hero-banner .hero-title {
              font-size: 1.1rem !important;
          }
          .hero-card p, .hero-banner .hero-subtitle {
              font-size: 0.78rem !important;
          }

          /* ── Session stats grid in sidebar: keep 2x2 ─── */
          .stats-strip {
              grid-template-columns: repeat(2, 1fr) !important;
              gap: 6px !important;
          }

          /* ── SOC / Scanner custom components ─────────── */
          iframe {
              max-width: 100% !important;
              border-radius: 12px !important;
          }

          /* ── Containers / cards ───────────────────────── */
          [data-testid="stVerticalBlock"] >
          [data-testid="stVerticalBlockBorderWrapper"] {
              border-radius: 12px !important;
          }

          /* ── Alerts / info / warning boxes ───────────── */
          [data-testid="stAlert"] {
              padding: 0.5rem 0.7rem !important;
              font-size: 0.78rem !important;
              border-radius: 10px !important;
              overflow-wrap: break-word !important;
              word-break: break-word !important;
          }

          /* ── Spinner text ──────────────────────────────── */
          [data-testid="stSpinner"] p {
              font-size: 0.78rem !important;
          }

          /* ── Topbar: compact on mobile ──────────────── */
          div[style*="justify-content:space-between"][style*="border-bottom"] {
              padding: 0.4rem 0.6rem !important;
              margin-bottom: 0.5rem !important;
              flex-wrap: wrap !important;
          }
          div[style*="justify-content:space-between"][style*="border-bottom"] h2 {
              font-size: 0.95rem !important;
          }
          div[style*="justify-content:space-between"][style*="border-bottom"] div[style*="font-size:0.78rem"] {
              font-size: 0.65rem !important;
          }
          div[style*="justify-content:space-between"][style*="border-bottom"] div[style*="width:40px"] {
              width: 30px !important;
              height: 30px !important;
          }
          div[style*="justify-content:space-between"][style*="border-bottom"] svg {
              width: 16px !important;
              height: 16px !important;
          }

          /* ── Sidebar brand area ───────────────────────── */
          section[data-testid="stSidebar"] div[style*="width:60px"][style*="height:60px"] {
              width: 40px !important;
              height: 40px !important;
          }
          section[data-testid="stSidebar"] h3 {
              font-size: 0.95rem !important;
          }

          /* ── Slider touch targets ─────────────────────── */
          [data-testid="stSlider"] [role="slider"] {
              width: 28px !important;
              height: 28px !important;
          }

          /* ── Metric cards ──────────────────────────────── */
          .metric-card {
              padding: 10px 12px !important;
              border-radius: 10px !important;
          }

          /* ── JSON / stMetric: compact ──────────────────── */
          [data-testid="stJson"] {
              overflow-x: auto !important;
              max-width: 100% !important;
              font-size: 0.72rem !important;
          }
          [data-testid="stMetricValue"] {
              font-size: 1.2rem !important;
          }
          [data-testid="stMetricLabel"] {
              font-size: 0.7rem !important;
          }

          /* ── Markdown tables ───────────────────────────── */
          .stMarkdown table {
              display: block !important;
              overflow-x: auto !important;
              -webkit-overflow-scrolling: touch !important;
              max-width: 100% !important;
          }
          .stMarkdown table th,
          .stMarkdown table td {
              font-size: 0.74rem !important;
              padding: 0.35rem 0.5rem !important;
              white-space: nowrap !important;
          }

          /* ── File uploader / download ──────────────────── */
          [data-testid="stFileUploader"] { width: 100% !important; }
          [data-testid="stFileUploader"] section { padding: 0.8rem !important; }
          [data-testid="stDownloadButton"] > button {
              width: 100% !important;
              min-height: 48px !important;
          }

          /* ── Checkbox / radio: tap area ─────────────── */
          [data-testid="stCheckbox"],
          [data-testid="stRadio"] label {
              min-height: 44px !important;
              display: flex !important;
              align-items: center !important;
          }

          /* ── Tab panel padding ──────────────────────── */
          [data-testid="stTabPanel"] {
              padding: 0.3rem 0 !important;
          }
        }

        /* ═══════════════════════════════════════════════════
           SMALL PHONES — screens up to 390px (iPhone SE,
           Galaxy A series)
           ═══════════════════════════════════════════════════ */

        @media screen and (max-width: 390px) {
          .main .block-container {
              padding: 0.4rem 0.5rem 2rem !important;
          }
          h1 { font-size: 1.2rem !important; }
          h2 { font-size: 1.05rem !important; }
          h3 { font-size: 0.95rem !important; }
          [data-testid="stTabsTab"] {
              font-size: 0.68rem !important;
              padding: 0.3rem 0.45rem !important;
          }
        }

        /* ═══════════════════════════════════════════════════
           iOS SAFARI — specific fixes
           ═══════════════════════════════════════════════════ */

        /* Prevent iOS rubber-band scroll causing layout shift */
        html {
          -webkit-overflow-scrolling: touch;
          overscroll-behavior: none;
        }

        /* Fix iOS notch / safe area padding */
        .main .block-container {
          padding-bottom: max(2rem, env(safe-area-inset-bottom)) !important;
          padding-left: max(0.75rem, env(safe-area-inset-left)) !important;
          padding-right: max(0.75rem, env(safe-area-inset-right)) !important;
        }

        /* Prevent iOS tap highlight flash on buttons */
        * {
          -webkit-tap-highlight-color: transparent;
          -webkit-touch-callout: none;
        }
        /* Re-enable text selection where needed */
        input, textarea, [contenteditable] {
          -webkit-touch-callout: default !important;
          -webkit-user-select: text !important;
        }

        /* Fix 100vh bug on iOS Safari (address bar eats space) */
        .main {
          min-height: -webkit-fill-available !important;
        }

        /* ===================================================================
           BASE COMPONENT STYLES (needed for classes used in App.py)
           =================================================================== */
        .hero-card {
          background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
          border: 1px solid rgba(56, 189, 248, 0.15);
          border-radius: 16px;
          padding: 2rem 2.5rem;
          margin-bottom: 1.5rem;
          position: relative;
          overflow: hidden;
        }
        .hero-card::after {
          content: '';
          position: absolute;
          bottom: 0; left: 0;
          width: 100%; height: 2px;
          background: linear-gradient(90deg, transparent, #38bdf8, transparent);
          animation: scan-line 3s ease-in-out infinite;
        }

        .metric-card {
          background: #111827;
          border: 1px solid #1e293b;
          border-radius: 12px;
          padding: 16px 20px;
          margin-bottom: 12px;
        }

        </style>
    """, unsafe_allow_html=True)


def render_topbar():
    """Render the top navigation/branding bar."""
    st.markdown("""
        <div style="display:flex;justify-content:space-between;align-items:center;padding:0.8rem 1rem;border-bottom:1px solid var(--border-subtle);margin-bottom:1.5rem;">
            <div style="display:flex;align-items:center;gap:1rem;">
                <div style="width:40px;height:40px;border-radius:var(--radius-sm);background:linear-gradient(135deg,var(--accent-cyan),var(--accent-violet));display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow-glow);">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
                <div>
                    <h2 style="margin:0;font-size:1.3rem;">Safeguard-AI Lite</h2>
                    <div style="color:var(--text-secondary);font-size:0.78rem;">Security Intelligence Platform</div>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar with live session stats and nav hints."""
    with st.sidebar:
        # Brand
        st.markdown("""
            <div style="text-align:center;padding:1rem 0;">
                <div style="width:60px;height:60px;margin:0 auto 1rem;border-radius:var(--radius-md);background:var(--bg-secondary);border:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow-glow);">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
                <h3 style="margin:0;font-size:1.2rem;">Safeguard-AI</h3>
                <div style="color:var(--accent-cyan);font-size:0.7rem;font-weight:600;letter-spacing:2px;margin-top:0.5rem;">ANALYST CONSOLE</div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # Auth status
        auth_user = st.session_state.get("auth_user")
        if auth_user:
            st.markdown(f"""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:0.5rem 0.75rem;background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.2);border-radius:var(--radius-sm);">
                    <span style="font-size:0.8rem;color:#34d399;">👤 {auth_user}</span>
                    <span style="font-size:0.75rem;color:#34d399;font-weight:600;">● Signed In</span>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:0.5rem 0.75rem;background:var(--bg-tertiary);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);">
                    <span style="font-size:0.8rem;color:var(--text-secondary);">System Status</span>
                    <span style="font-size:0.8rem;color:var(--accent-emerald);font-weight:500;">● Operational</span>
                </div>
            """, unsafe_allow_html=True)

        # Session stats grid
        scan_history = st.session_state.get("deep_scan_history", [])
        scan_count   = len(scan_history) if isinstance(scan_history, list) else 0
        live_count   = len(st.session_state.get("live_history", []))
        total_vulns  = st.session_state.get("total_vulns_found", 0)
        total_crits  = st.session_state.get("total_critical_found", 0)

        st.markdown(f"""
            <div style="margin-top:1rem;padding:1rem;background:var(--bg-glass);border:1px solid var(--border-subtle);border-radius:var(--radius-md);">
                <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:0.75rem;">📊 Session Stats</div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                    <div style="text-align:center;padding:8px;background:var(--bg-tertiary);border-radius:8px;">
                        <div style="font-size:1.4rem;font-family:var(--font-mono);color:var(--accent-cyan);font-weight:700;">{scan_count}</div>
                        <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Deep Scans</div>
                    </div>
                    <div style="text-align:center;padding:8px;background:var(--bg-tertiary);border-radius:8px;">
                        <div style="font-size:1.4rem;font-family:var(--font-mono);color:var(--accent-violet);font-weight:700;">{live_count}</div>
                        <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">ML Predictions</div>
                    </div>
                    <div style="text-align:center;padding:8px;background:var(--bg-tertiary);border-radius:8px;">
                        <div style="font-size:1.4rem;font-family:var(--font-mono);color:var(--accent-amber);font-weight:700;">{total_vulns}</div>
                        <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Vulns Found</div>
                    </div>
                    <div style="text-align:center;padding:8px;background:var(--bg-tertiary);border-radius:8px;">
                        <div style="font-size:1.4rem;font-family:var(--font-mono);color:var(--accent-rose);font-weight:700;">{total_crits}</div>
                        <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Critical</div>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        # Last scan card
        last_target    = st.session_state.get("deep_scan_target", "")
        last_result    = st.session_state.get("deep_scan_result", {})
        last_grade     = last_result.get("risk_grade", "—") if isinstance(last_result, dict) else "—"
        last_score     = last_result.get("overall_risk_score", "—") if isinstance(last_result, dict) else "—"
        last_analysis  = st.session_state.get("deep_scan_analysis", {})
        last_risk      = last_analysis.get("risk_level", "—") if isinstance(last_analysis, dict) else "—"

        grade_colors = {"A+":"#22c55e","A":"#34d399","B":"#38bdf8","C":"#eab308","D":"#f59e0b","F":"#ef4444"}
        risk_colors  = {"Critical":"#fb7185","High":"#fbbf24","Medium":"#38bdf8","Low":"#34d399","Minimal":"#34d399"}
        grade_col = grade_colors.get(last_grade, "#475569")
        risk_col  = risk_colors.get(last_risk, "#475569")

        if last_target:
            score_html = f'<span style="font-size:0.75rem;color:var(--text-secondary);">Score: {last_score}</span>' if last_score != "—" else ""
            st.markdown(f"""
                <div style="margin-top:1rem;padding:1rem;background:var(--bg-glass);border:1px solid var(--border-subtle);border-radius:var(--radius-md);">
                    <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:0.5rem;">🔬 Last Deep Scan</div>
                    <div style="font-size:0.85rem;font-family:var(--font-mono);color:var(--text-primary);margin-bottom:0.5rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{last_target}">{last_target[:26]}{'…' if len(last_target)>26 else ''}</div>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
                        <span style="font-size:0.75rem;font-weight:700;color:{grade_col};background:rgba(0,0,0,0.2);padding:2px 8px;border-radius:4px;">Grade: {last_grade}</span>
                        <span style="font-size:0.75rem;font-weight:600;color:{risk_col};background:rgba(0,0,0,0.2);padding:2px 8px;border-radius:4px;">{last_risk}</span>
                        {score_html}
                    </div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("""
            <div style="padding:0.75rem;font-size:0.76rem;color:var(--text-muted);text-align:center;">
                Use the <strong style="color:var(--accent-cyan)">sidebar pages</strong> below<br>or the <strong style="color:var(--accent-cyan)">tabs above</strong> to navigate.
            </div>
        """, unsafe_allow_html=True)




def render_api_error(error: Any):
    """Render a styled API error message."""
    error_msg = str(error) if error else "An unknown error occurred."

    st.markdown(f"""
        <div style="padding: 1rem; background: rgba(251, 113, 133, 0.1); border-left: 4px solid var(--accent-rose); border-radius: var(--radius-sm); margin: 1rem 0;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                <span style="font-size: 1.2rem;">❌</span>
                <span style="font-weight: 600; color: var(--accent-rose);">API Error</span>
            </div>
            <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-secondary); word-break: break-all;">
                {error_msg[:500]}
            </div>
        </div>
    """, unsafe_allow_html=True)


def build_prediction_results_frame(result: Any) -> Optional[pd.DataFrame]:
    """
    Convert prediction API result to a styled DataFrame.

    Args:
        result: Full prediction result dict (with a 'predictions' key) OR a list of prediction dicts.

    Returns:
        Pandas DataFrame or empty DataFrame if results are empty.
    """
    if result is None:
        return pd.DataFrame()

    # Accept both the full result dict and a bare list
    if isinstance(result, dict):
        rows = result.get("predictions", [])
    elif isinstance(result, list):
        rows = result
    else:
        return pd.DataFrame()

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    return df


def render_first_row_explanation(result: Any):
    """
    Render SHAP / feature-importance explanation for the first prediction row.

    Args:
        result: Full prediction result dict returned by the API.
    """
    if not result:
        return

    predictions = result.get("predictions", [])
    if not predictions:
        return

    first = predictions[0]

    # Show confidence + label inline
    label = first.get("predicted_label", "Unknown")
    confidence = first.get("confidence", 0.0)

    st.markdown("**First-Row Explanation**")
    col1, col2 = st.columns(2)
    col1.metric("Predicted Label", label)
    col2.metric("Confidence", f"{confidence:.2%}" if isinstance(confidence, float) else str(confidence))

    # Top contributions (SHAP)
    contributions = first.get("top_contributions", [])
    if contributions:
        st.markdown("**Top Feature Contributions (SHAP)**")
        contrib_df = pd.DataFrame(contributions)
        st.dataframe(contrib_df, use_container_width=True, hide_index=True)

    # Class probabilities breakdown
    class_probs = first.get("class_probabilities", {})
    if class_probs:
        import matplotlib.pyplot as plt
        prob_df = pd.DataFrame({
            "class_name": list(class_probs.keys()),
            "probability": list(class_probs.values()),
        }).sort_values(by="probability", ascending=True)
        fig, ax = plt.subplots(figsize=(8, max(3, 0.35 * len(prob_df))))
        ax.barh(prob_df["class_name"], prob_df["probability"], color="#38bdf8")
        ax.set_title("Class Probabilities (First Row)")
        ax.set_xlim(0, 1)
        st.pyplot(fig, use_container_width=True)


def render_severity_badge(severity: str) -> str:
    """Return HTML for a severity badge."""
    severity_lower = severity.lower()
    css_class = f"severity-{severity_lower}" if severity_lower in ("critical", "high", "medium", "low") else "severity-low"
    return f'<span class="{css_class}">{severity}</span>'


def render_risk_grade_badge(grade: str) -> str:
    """Return HTML for a risk grade badge."""
    grade_lower = grade.lower().replace("+", "")
    if grade_lower in ("a",):
        css_class = "risk-grade-a"
    elif grade_lower == "b":
        css_class = "risk-grade-b"
    elif grade_lower == "c":
        css_class = "risk-grade-c"
    elif grade_lower == "d":
        css_class = "risk-grade-d"
    else:
        css_class = "risk-grade-f"
    return f'<div class="{css_class}">{grade}</div>'


def render_metric_strip(metrics: List[Dict[str, Any]]):
    """
    Render a horizontal strip of metric cards.

    Args:
        metrics: List of dicts with 'value' and 'label' keys.
    """
    items_html = ""
    for m in metrics[:4]:
        value = m.get("value", "—")
        label = m.get("label", "")
        color = m.get("color", "#38bdf8")
        items_html += f"""
            <div class="metric-strip-item">
                <span class="metric-strip-value" style="color: {color};">{value}</span>
                <span class="metric-strip-label">{label}</span>
            </div>
        """

    st.markdown(f'<div class="metric-strip">{items_html}</div>', unsafe_allow_html=True)


def render_scan_terminal(lines: List[str]):
    """
    Render a terminal-style output block.

    Args:
        lines: List of terminal output lines.
    """
    content = "\n".join(lines)
    st.markdown(f'<div class="scan-terminal"><pre>{content}</pre></div>', unsafe_allow_html=True)


def render_vuln_card(vuln: Dict[str, Any]):
    """
    Render a single vulnerability card.

    Args:
        vuln: Vulnerability dictionary with title, severity, description, etc.
    """
    severity = vuln.get("severity", "low").lower()
    title = vuln.get("title", "Unknown Vulnerability")
    description = vuln.get("description", "")
    vuln_id = vuln.get("id", "")

    st.markdown(f"""
        <div class="vuln-card vuln-{severity}">
            <div class="vuln-card-title">
                {vuln_id}: {title}
                <span class="severity-{severity}" style="margin-left: 8px;">{severity.upper()}</span>
            </div>
            <div class="vuln-card-desc">{description[:200]}</div>
        </div>
    """, unsafe_allow_html=True)


def render_remediation_item(priority: int, action: str, effort: str = "Medium", impact: str = "Medium"):
    """
    Render a single remediation roadmap item.

    Args:
        priority: Priority number.
        action: The remediation action text.
        effort: Effort level (Low/Medium/High).
        impact: Impact level (Critical/High/Medium/Low).
    """
    effort_class = f"effort-{effort.lower()}" if effort.lower() in ("low", "medium", "high") else "effort-medium"
    impact_class = f"impact-{impact.lower()}" if impact.lower() in ("critical", "high", "medium") else "impact-medium"

    st.markdown(f"""
        <div class="remediation-item">
            <div class="remediation-number">{priority}</div>
            <div class="remediation-content">
                <div class="remediation-action">{action[:250]}</div>
                <div class="remediation-badges">
                    <span class="remediation-badge {effort_class}">Effort: {effort}</span>
                    <span class="remediation-badge {impact_class}">Impact: {impact}</span>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)