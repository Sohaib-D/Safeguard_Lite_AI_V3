# app.py  ─ Single-Process Entry Point for Safeguard-AI Lite
# ─────────────────────────────────────────────────────────────
# This file starts the FastAPI backend in a background thread,
# then runs the Streamlit frontend in the same process.
# Deploy this on Streamlit Cloud or any single-container host.
#
# Usage:
#   streamlit run app.py
# ─────────────────────────────────────────────────────────────

import os
import sys
import threading
import time
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── 1. Start FastAPI backend in a daemon thread ───────────────
def _run_backend():
    """Start uvicorn in a background thread (non-blocking)."""
    import uvicorn
    uvicorn.run(
        "backend.api.main:app",
        host="127.0.0.1",
        port=8000,
        log_level="warning",   # keep noise low in Streamlit logs
        reload=False,          # no reloader inside a thread
    )

# Only start the backend once (Streamlit reruns this file on every interaction)
_BACKEND_STARTED_KEY = "_safeguard_backend_started"
if not os.environ.get(_BACKEND_STARTED_KEY):
    os.environ[_BACKEND_STARTED_KEY] = "1"
    _backend_thread = threading.Thread(target=_run_backend, daemon=True, name="safeguard-backend")
    _backend_thread.start()
    # Give it a moment to bind the port before Streamlit starts making API calls
    time.sleep(3)

# ── 2. Set the API base URL so the frontend client knows where to connect ──
os.environ.setdefault("SAFEGUARD_API_BASE_URL", "http://127.0.0.1:8000")

# ── 3. Hand off to the Streamlit frontend ────────────────────
# Import and run frontend/App.py as a module (not subprocess)
import frontend.App as _app_module  # noqa: E402

# Streamlit has already imported and executed this file's top-level code,
# so we call main() directly here to render the UI.
if hasattr(_app_module, "main"):
    _app_module.main()
