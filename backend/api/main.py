import logging
import json
import threading
from contextlib import asynccontextmanager
from typing import Any, Dict
from fastapi import FastAPI, Request, UploadFile, File, APIRouter, Body, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.orm import Session
import httpx

from backend.core.config import settings
from backend.core.logging_config import configure_logging
from backend.core.security import create_access_token
from backend.db.database import Base, engine, verify_connection
from backend.db.models import DetectionAlert, ScanResult
from backend.db.session import get_db, transaction_scope
from backend.dependencies.auth import get_current_user
from backend.services.auth_service import AuthService
from backend.services.ai_service import AIService
from backend.services.report_generator import ReportGenerator
from backend.api.routes import auth, alerts, monitoring, websocket
from backend.network.active_scanner import ActiveScanner
from backend.network.packet_capture import PacketCaptureEngine
from backend.network.deep_scanner import DeepScanner
from backend.schemas.auth import TokenResponse
from backend.schemas.auth_schema import UserCreate, UserLogin, Token
from backend.services.security_intelligence import SecurityIntelligence

# 1. Initialize Logging
configure_logging()
logger = logging.getLogger("safeguard.api")

# 2. Lifespan (replaces deprecated on_event startup/shutdown)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────
    logger.info("Starting Safeguard-AI Lite Backend...")

    if not verify_connection():
        logger.critical("Database unreachable. Exiting...")
        raise RuntimeError("Database connection failed during startup.")

    Base.metadata.create_all(bind=engine)
    logger.info("Schema synchronization complete.")

    with transaction_scope() as db:
        auth_svc = AuthService(db)
        if not auth_svc.user_exists(settings.ADMIN_USERNAME):
            logger.info("Seeding initial admin user...")
            auth_svc.create_user(
                username=settings.ADMIN_USERNAME,
                password=settings.ADMIN_PASSWORD,
                is_admin=True,
            )

    yield  # Application runs here

    # ── Shutdown ─────────────────────────────────────────────
    logger.info("Safeguard-AI Lite shutting down gracefully.")


# 3. Initialize FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)

# 4. Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 5. Global Exception Handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Our engineers are investigating."},
    )

# 6. Health Check
@app.get("/", tags=["System"])
async def root():
    return {
        "message": f"Welcome to {settings.APP_NAME} API",
        "docs": "/api/docs",
        "version": settings.APP_VERSION,
    }

@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "database": "connected",
    }

# 7. API V1 Router
v1_router = APIRouter()

# Include feature routers
v1_router.include_router(auth.router, prefix="/auth")
v1_router.include_router(alerts.router)
v1_router.include_router(monitoring.router)
v1_router.include_router(websocket.router)

# Recon router (deep scanner with background tasks + status polling)
from backend.api.routes import recon as recon_module
v1_router.include_router(recon_module.router)

# Shared helpers

def _build_model_info() -> Dict[str, Any]:
    """Return model metadata derived from the actual model bundle on disk."""
    from backend.ml.model_loader import ModelLoader
    bundle = ModelLoader().get_model()
    if isinstance(bundle, dict):
        label_classes = bundle.get("label_classes", ["Normal", "DDoS", "BruteForce", "PortScan"])
        ct = bundle.get("preprocessor")
        num_cols, cat_cols = [], []
        if ct is not None:
            for name, _, cols in ct.transformers_:
                if name == "num":
                    num_cols = list(cols)
                elif name == "cat":
                    cat_cols = list(cols)
    else:
        label_classes = ["Normal", "DDoS", "BruteForce", "PortScan"]
        num_cols = [f"f{i}" for i in range(10)]
        cat_cols = ["service"]

    return {
        "model_name": bundle.get("model_name", "random_forest") if isinstance(bundle, dict) else "unknown",
        "framework": "FastAPI",
        "backend": "PostgreSQL",
        "version": settings.APP_VERSION,
        "label_classes": label_classes,
        "feature_count": len(num_cols) + len(cat_cols),
        "raw_input_schema": {
            "numeric_columns": num_cols,
            "categorical_columns": cat_cols,
        },
    }


def _perform_predictions(records: list[dict], db=None, source_type: str = "live", user_id=None) -> dict:
    """Run records through the ML model. Persists each result to DB when db is supplied."""
    from backend.ml.model_loader import ModelLoader
    from backend.ml.predictor import ThreatPredictor
    from backend.db.models import ScanResult as ScanResultModel

    loader = ModelLoader()
    predictor = ThreatPredictor(loader)

    predictions = []
    labels_count: dict[str, int] = {}

    for i, record in enumerate(records):
        res = predictor.predict(record)
        label = res.get("label", "Unknown")
        confidence = res.get("confidence", 0.0)

        predictions.append(
            {
                "row_index": i,
                "predicted_label": label,
                "confidence": round(confidence, 4),
                "recommendation_severity": "Alert" if label != "Normal" else "Normal",
                "recommendations": ["Review logs", "Check source IP"] if label != "Normal" else [],
                "shap_values": res.get("all_probs", {}),
            }
        )
        labels_count[label] = labels_count.get(label, 0) + 1

        if db is not None:
            try:
                scan = ScanResultModel(
                    source_type=source_type,
                    predicted_label=label,
                    confidence=confidence,
                    feature_data=record,
                    explanation=res.get("all_probs"),
                    created_by=user_id,
                )
                db.add(scan)
            except Exception as _exc:
                logger.warning(f"Failed to stage prediction row {i}: {_exc}")

    if db is not None:
        try:
            db.commit()
        except Exception as _ce:
            logger.warning(f"DB commit failed for live predictions: {_ce}")
            db.rollback()

    non_normal = {k: v for k, v in labels_count.items() if k != "Normal"}
    return {
        "predictions": predictions,
        "summary": {
            "prediction_count": len(predictions),
            "labels": labels_count,
            "recommended_actions": (
                ["Monitor suspicious IPs", "Review flagged events"] if non_normal else []
            ),
        },
    }


def _predict_csv_bytes(content: bytes, db=None, user_id=None) -> dict:
    """Run CSV through the model, persist each row to scan_results, return predictions."""
    import io
    import pandas as pd
    from backend.ml.model_loader import ModelLoader
    from backend.ml.predictor import ThreatPredictor
    from backend.db.models import ScanResult as ScanResultModel

    loader = ModelLoader()
    predictor = ThreatPredictor(loader)
    bundle = loader.get_model()

    # Determine expected raw columns from the model bundle
    expected_num: list[str] = [f"f{i}" for i in range(10)]
    expected_cat: list[str] = ["service"]
    if isinstance(bundle, dict):
        ct = bundle.get("preprocessor")
        if ct is not None:
            for name, _, cols in ct.transformers_:
                if name == "num":
                    expected_num = list(cols)
                elif name == "cat":
                    expected_cat = list(cols)

    df = pd.read_csv(io.BytesIO(content))

    # ── Column normalisation ──────────────────────────────────────────────────
    # Drop ground-truth label if present (not a feature)
    df.drop(columns=["label"], errors="ignore", inplace=True)

    # Rename common protocol/service aliases → "service"
    for alias in ("proto", "protocol", "Proto", "Protocol"):
        if alias in df.columns and "service" not in df.columns:
            df.rename(columns={alias: "service"}, inplace=True)
            break

    # Fill any missing expected numeric columns with 0.0
    for col in expected_num:
        if col not in df.columns:
            df[col] = 0.0

    # Fill missing categorical columns with most-common training value
    for col in expected_cat:
        if col not in df.columns:
            df[col] = "http"
    # ─────────────────────────────────────────────────────────────────────────

    predictions = []
    labels_count: dict[str, int] = {}

    for i, row in df.iterrows():
        if i >= 100:
            break
        record = row.to_dict()
        res = predictor.predict(record)
        label = res.get("label", "Unknown")
        confidence = res.get("confidence", 0.0)

        row_pred = {
            "row_index": i,
            "predicted_label": label,
            "confidence": round(confidence, 4),
            "recommendation_severity": "Alert" if label != "Normal" else "Normal",
            "recommendations": ["Review logs", "Check source IP"] if label != "Normal" else [],
        }
        predictions.append(row_pred)
        labels_count[label] = labels_count.get(label, 0) + 1

        # Persist to DB when a session is available
        if db is not None:
            try:
                scan = ScanResultModel(
                    source_type="csv",
                    predicted_label=label,
                    confidence=confidence,
                    feature_data=record,
                    explanation=res.get("all_probs"),
                    created_by=user_id,
                )
                db.add(scan)
            except Exception as _db_exc:
                logger.warning(f"Failed to persist row {i} to DB: {_db_exc}")

    if db is not None:
        try:
            db.commit()
        except Exception as _commit_exc:
            logger.warning(f"DB commit failed for CSV upload: {_commit_exc}")
            db.rollback()

    return {
        "predictions": predictions,
        "summary": {
            "prediction_count": len(predictions),
            "labels": labels_count,
            "recommended_actions": (
                ["Investigate non-normal traffic", "Check source IPs"]
                if any(k != "Normal" for k in labels_count)
                else []
            ),
        },
    }

# Model Info
@v1_router.get("/model_info", tags=["System"])
async def get_model_info(current_user: Any = Depends(get_current_user)):
    return _build_model_info()

# Capture Control
capture_engine = PacketCaptureEngine()

@v1_router.get("/capture/stats", tags=["Capture"])
async def get_capture_stats(current_user: Any = Depends(get_current_user)):
    return {
        "running": capture_engine.is_running,
        "interface": capture_engine.interface or "Default",
        "queue_size": 0,
        "flows_count": 0,
        "ip_count": 0,
    }

@v1_router.post("/capture/start", tags=["Capture"])
async def start_capture_route(
    payload: dict = Body(...), current_user: Any = Depends(get_current_user)
):
    interface = payload.get("interface")
    capture_engine.interface = interface
    if not capture_engine.is_running:
        threading.Thread(target=capture_engine.start_capture, daemon=True).start()
    return {"status": "started", "interface": interface or "Default"}

@v1_router.post("/capture/stop", tags=["Capture"])
async def stop_capture_route(current_user: Any = Depends(get_current_user)):
    capture_engine.stop_capture()
    return {"status": "stopped"}

# NOTE: All /recon/* routes (scan, deep-scan, scan-status, analyze-scan, export-report)
# are handled by recon_module router included above.

# AI SOC
@v1_router.post("/ai/soc-analysis", tags=["AI SOC"])
async def ai_soc_analysis(payload: dict = Body(...), current_user: Any = Depends(get_current_user)):
    ai_svc = AIService()
    detection = payload.get("detection_result", {})
    label = detection.get("predicted_label", "Unknown")
    confidence = detection.get("confidence", 0.0)
    ts = str(detection.get("timestamp", "N/A"))

    prompt = (
        "You are a senior SOC analyst. Analyze this security detection payload and return ONLY "
        "valid JSON (no markdown, no preamble, no backticks) matching this exact schema:\n"
        "{\n"
        '  "threat_summary": "2-3 sentence plain-English overview",\n'
        '  "risk_assessment": "severity and likelihood statement",\n'
        '  "remediation_recommendations": ["action 1", "action 2", "action 3"],\n'
        '  "incident_timeline": [{"timestamp": "ISO8601", "event": "description", "detail": "optional"}],\n'
        '  "false_positive_analysis": "assessment of false-positive likelihood",\n'
        '  "correlated_events": [{"event_id": "id", "correlation_reason": "reason"}],\n'
        '  "shap_explanation": "plain-English feature importance explanation",\n'
        '  "incident_report": "full incident report paragraph"\n'
        "}\n\n"
        f"Detection payload: {json.dumps(payload, default=str)[:3000]}"
    )

    def _fallback() -> dict:
        return {
            "threat_summary": (
                f"The ML classifier detected a {label} event with "
                f"{confidence*100:.1f}% confidence. Manual analyst review is recommended."
            ),
            "risk_assessment": (
                "Medium – automated ML classification. "
                "Verify with packet-level evidence before escalating."
            ),
            "remediation_recommendations": [
                "Review firewall logs for the source IP",
                "Check for related alerts within the past 15 minutes",
                "Update IDS signatures if the pattern recurs",
            ],
            "incident_timeline": [
                {"timestamp": ts, "event": f"{label} classified", "detail": f"Confidence: {confidence:.2%}"},
            ],
            "false_positive_analysis": (
                "Cannot determine false-positive likelihood without full packet context. "
                "Treat as genuine until packet evidence disproves it."
            ),
            "correlated_events": [],
            "shap_explanation": (
                "SHAP data unavailable for this request. "
                "Run a live prediction with explanations enabled to see per-feature contributions."
            ),
            "incident_report": (
                f"At {ts}, Safeguard-AI classified a {label} event "
                f"(confidence {confidence:.2%}). Full packet-level investigation is pending."
            ),
        }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                ai_svc.base_url,
                headers={"Authorization": f"Bearer {ai_svc.api_key}"},
                json={
                    "model": ai_svc.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity expert. "
                                "Return ONLY valid JSON matching the requested schema. "
                                "No markdown fences, no extra keys, no preamble."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                    "max_tokens": 1500,
                },
                timeout=30.0,
            )
            resp.raise_for_status()
            ai_content = resp.json()["choices"][0]["message"]["content"]
            result = json.loads(ai_content) if isinstance(ai_content, str) else ai_content
            # Ensure all 8 required keys exist (fill missing with fallback values)
            fb = _fallback()
            for key in fb:
                if key not in result or not result[key]:
                    result[key] = fb[key]
            return result
    except Exception as e:
        logger.error(f"SOC AI analysis failed: {e}")
        return _fallback()

@v1_router.post("/ai/vulnerability-analysis", tags=["AI SOC"])
async def ai_vuln_analysis(payload: dict = Body(...), current_user: Any = Depends(get_current_user)):
    ai_svc = AIService()

    prompt = f"""
    Role: Defensive Security Analyst
    Task: Analyze the following non-invasive reconnaissance data and identify evidence-backed defensive findings.

    Target: {payload.get('target')}
    Open Ports: {payload.get('ports')}
    Security Configs Found: {payload.get('security_configs')}
    HTTP Headers: {payload.get('http_headers')}

    Instructions:
    1. Do not claim exploitability is verified.
    2. Open ports are exposure observations, not vulnerabilities by themselves.
    3. Missing WAF/CDN does not prove DDoS vulnerability.
    4. Missing CSP does not prove exploitable XSS.
    5. Public SSH does not imply weak passwords.
    6. Provide conservative findings with evidence and remediation.

    Output Format (JSON):
    {{
        "summary": "overall assessment",
        "vulnerabilities_found": true/false,
        "findings": [
            {{
                "port": 80,
                "service": "HTTP",
                "vulnerability": "description",
                "exploitation": "conservative risk scenario; say exploitability not verified",
                "confidence_score": 0.0,
                "evidence": "observed evidence",
                "remediation": "how to fix"
            }}
        ]
    }}"""

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                ai_svc.base_url,
                headers={"Authorization": f"Bearer {ai_svc.api_key}"},
                json={
                    "model": ai_svc.model,
                    "messages": [
                        {"role": "system", "content": "You are a defensive cybersecurity analyst. You MUST return ONLY valid JSON and must not claim verified exploitability without evidence."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
                timeout=30.0,
            )
            response.raise_for_status()
            ai_data = response.json()
            content = ai_data["choices"][0]["message"]["content"]
            if isinstance(content, str):
                return JSONResponse(content=json.loads(content))
            return JSONResponse(content=content)
    except Exception as e:
        logger.error(f"AI Vuln Analysis failed: {e}")
        return {
            "summary": "AI Analysis failed to generate a response. Please check manual scan results.",
            "vulnerabilities_found": False,
            "findings": [],
        }

# Predictions
@v1_router.post("/predict/records", tags=["ML Predictions"])
async def predict_records(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    records = payload.get("records", [])
    user_id = getattr(current_user, "id", None)
    return _perform_predictions(records, db=db, source_type="live", user_id=user_id)

@v1_router.post("/predict/csv", tags=["ML Predictions"])
async def predict_csv(
    file: UploadFile = File(...),
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    user_id = getattr(current_user, "id", None)
    return _predict_csv_bytes(content, db=db, user_id=user_id)

# ──────────────────────────────────────────────────────────────────────────────
# Cybersecurity Chatbot
# ──────────────────────────────────────────────────────────────────────────────

# Sensitive patterns that must NEVER leak
import re as _re
_SENSITIVE_PATTERNS = _re.compile(
    r"(password|passwd|api.?key|secret.?key|jwt.?secret|database.?url|"
    r"db.?password|access.?token|bearer|\.env|environment.?variable|"
    r"groq.?api|admin.?password|credentials)",
    _re.IGNORECASE,
)

_CHATBOT_SYSTEM_PROMPT = (
    "You are **Sohaib**, a senior Cybersecurity and Information Security expert at Safeguard-AI Lite. "
    "Your tone is professional, conversational, and helpful.\n\n"
    "## STRICT RULES — NEVER VIOLATE:\n"
    "1. For greetings (like 'Hi', 'How are you', 'What is your name'), respond naturally and politely, introduce yourself as Sohaib, "
    "and gracefully steer the conversation toward cybersecurity. KEEP GREETINGS EXTREMELY BRIEF (maximum 2-3 sentences).\n"
    "2. ONLY answer core questions about cybersecurity, information security, network security, "
    "threat analysis, vulnerability assessment, SOC operations, incident response, "
    "malware analysis, penetration testing concepts, and security best practices.\n"
    "3. For ANY off-topic question (coding help, math, general knowledge, jokes, recipes, etc.), "
    "politely decline and steer back: 'I specialize in cybersecurity topics only. How can I help with your security needs?'\n"
    "4. **NEVER** reveal, discuss, or generate: passwords, API keys, JWT secrets, database URLs, "
    "environment variables, .env file contents, authentication tokens, or ANY sensitive credentials. "
    "If asked, respond: 'I cannot share sensitive system information for security reasons.'\n"
    "5. When given scan results or report context, analyze them professionally.\n"
    "6. Keep ALL answers concise, actionable, and professional. Introductory replies and casual small talk MUST NOT exceed 2-3 sentences.\n"
    "7. Use markdown formatting for readability.\n"
    "8. If the user asks about platform features, explain Safeguard-AI Lite capabilities "
    "(upload CSV, live predictions, deep security scanner, active scanner, SOC dashboard, SHAP explanations).\n"
)


@app.post("/chat", tags=["Chatbot"])
async def chatbot_endpoint(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
):
    """Cybersecurity expert chatbot endpoint. Requires authentication."""
    ai_svc = AIService()
    message = str(payload.get("message", "")).strip()
    context = payload.get("context", {})
    history = payload.get("history", [])

    if not message:
        return {"reply": "Please type a question about cybersecurity."}

    # Security gate: block requests for sensitive data
    if _SENSITIVE_PATTERNS.search(message):
        # Check if the user is asking FOR credentials vs asking ABOUT security concepts
        ask_patterns = _re.compile(
            r"(show|give|tell|reveal|print|display|leak|dump|what.?is.?the|what.?is.?my)\s+"
            r".*(password|api.?key|secret|token|credential|\.env|database.?url)",
            _re.IGNORECASE,
        )
        if ask_patterns.search(message):
            return {
                "reply": (
                    "🔒 **Security Policy**: I cannot share sensitive system information "
                    "such as passwords, API keys, database credentials, or environment variables. "
                    "This is enforced for your protection.\n\n"
                    "If you have a cybersecurity question, I'm happy to help!"
                )
            }

    # Build context string from session data (non-sensitive only)
    context_parts = []
    if context.get("scan_results"):
        ctx = context["scan_results"]
        # Sanitize: remove any keys that might contain sensitive data
        safe_ctx = {k: v for k, v in ctx.items()
                    if not _SENSITIVE_PATTERNS.search(str(k))}
        context_parts.append(f"Recent scan results: {json.dumps(safe_ctx, default=str)[:2000]}")
    if context.get("prediction_summary"):
        context_parts.append(f"Prediction summary: {json.dumps(context['prediction_summary'], default=str)[:1000]}")
    if context.get("soc_alerts"):
        context_parts.append(f"SOC alerts: {json.dumps(context['soc_alerts'], default=str)[:1000]}")

    user_prompt = message
    if context_parts:
        user_prompt += "\n\n---\nPlatform Context (for reference):\n" + "\n".join(context_parts)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                ai_svc.base_url,
                headers={"Authorization": f"Bearer {ai_svc.api_key}"},
                json={
                    "model": ai_svc.model,
                    "messages": [
                        {"role": "system", "content": _CHATBOT_SYSTEM_PROMPT}
                    ] + [
                        {"role": h.get("role") if h.get("role") in ["user", "assistant"] else "user", 
                         "content": str(h.get("content", ""))[:1000]}
                        for h in history[-10:]
                    ] + [
                        {"role": "user", "content": user_prompt[:4000]}
                    ],
                    "temperature": 0.4,
                    "max_tokens": 800,
                },
                timeout=25.0,
            )
            resp.raise_for_status()
            reply = resp.json()["choices"][0]["message"]["content"]

            # Post-response safety: scrub any accidental leaks
            for pattern in [
                r"gsk_[A-Za-z0-9]{20,}",       # Groq API keys
                r"sk-[A-Za-z0-9]{20,}",         # OpenAI keys
                r"postgresql://[^\s]+",          # DB URLs
                r"eyJ[A-Za-z0-9_-]{20,}",       # JWT tokens
            ]:
                reply = _re.sub(pattern, "[REDACTED]", reply)

            return {"reply": reply}
    except Exception as e:
        logger.error(f"Chatbot error: {e}")
        return {
            "reply": (
                "⚠️ I'm temporarily unable to process your request. "
                "Please try again in a moment. If the issue persists, "
                "check that the backend AI service is configured correctly."
            )
        }


# Root compatibility aliases


@app.post("/auth/create-admin", response_model=TokenResponse, tags=["Authentication"])
async def create_admin(payload: UserCreate):
    with transaction_scope() as db:
        auth_svc = AuthService(db)
        if auth_svc.user_exists(payload.username):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
        user = auth_svc.create_user(
            username=payload.username,
            password=payload.password,
            is_admin=True,
        )
        access_token = create_access_token(subject=user.id)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "username": user.username,
            "is_admin": user.is_admin,
        }

@app.post("/auth/login", response_model=Token, tags=["Authentication"])
async def login(payload: UserLogin, db: Session = Depends(get_db)):
    auth_svc = AuthService(db)
    user = auth_svc.authenticate_user(payload.username, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=user.id)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
    }

@app.get("/model_info", tags=["System"])
async def model_info_root(current_user: Any = Depends(get_current_user)):
    return _build_model_info()

@app.get("/stats", tags=["System"])
async def stats_root(current_user: Any = Depends(get_current_user), db: Session = Depends(get_db)):
    from sqlalchemy import func
    total_predictions = db.query(ScanResult).count()
    total_uploads = db.query(ScanResult).filter(ScanResult.source_type == "csv").count()
    avg_raw = db.query(func.avg(ScanResult.confidence)).scalar()
    avg_confidence = round(float(avg_raw), 4) if avg_raw is not None else 0.0
    latest_dt = db.query(func.max(ScanResult.created_at)).scalar()
    latest_prediction_at = latest_dt.isoformat() if latest_dt else None
    label_rows = (
        db.query(ScanResult.predicted_label, func.count(ScanResult.id))
        .group_by(ScanResult.predicted_label).all()
    )
    predictions_by_label = {lbl: cnt for lbl, cnt in label_rows} or {"Normal": 0}
    return {
        "total_alerts": db.query(DetectionAlert).count(),
        "total_scans": total_predictions,
        "total_predictions": total_predictions,
        "total_uploads": total_uploads,
        "avg_confidence": avg_confidence,
        "latest_prediction_at": latest_prediction_at,
        "critical_threats": db.query(DetectionAlert).filter(DetectionAlert.severity == "CRITICAL").count(),
        "predictions_by_label": predictions_by_label,
    }

@app.post("/predict", tags=["ML Predictions"])
async def predict_root(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    records = payload.get("records", [])
    user_id = getattr(current_user, "id", None)
    return _perform_predictions(records, db=db, source_type="live", user_id=user_id)

@app.post("/upload", tags=["ML Predictions"])
async def upload_root(
    file: UploadFile = File(...),
    current_user: Any = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    user_id = getattr(current_user, "id", None)
    return _predict_csv_bytes(content, db=db, user_id=user_id)

@app.post("/capture/start", tags=["Capture"])
async def start_capture_root(payload: dict = Body(...), current_user: Any = Depends(get_current_user)):
    interface = payload.get("interface")
    capture_engine.interface = interface
    if not capture_engine.is_running:
        threading.Thread(target=capture_engine.start_capture, daemon=True).start()
    return {"status": "started", "interface": interface or "Default"}

@app.post("/capture/stop", tags=["Capture"])
async def stop_capture_root(current_user: Any = Depends(get_current_user)):
    capture_engine.stop_capture()
    return {"status": "stopped"}

# Deep Scan Analysis
@v1_router.post("/recon/analyze-scan", tags=["Deep Security Scan"])
async def analyze_scan_result(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
):
    """
    Analyze a deep scan result using AI-powered security intelligence.
    
    Accepts a payload containing a "scan_result" key with the full deep scan output.
    Returns comprehensive analysis, client offering assessment, and PDF-ready report data.
    """
    intel = SecurityIntelligence()
    scan_result = payload.get("scan_result", {})
    
    if not scan_result:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="scan_result is required in payload")
    
    analysis = await intel.analyze_scan(scan_result)
    client_angle = await intel.assess_for_client_offering(analysis)
    report_data = await intel.generate_pdf_report_data(scan_result, analysis)
    
    return {
        "analysis": analysis,
        "client_offering": client_angle,
        "report_data": report_data,
    }

@v1_router.post("/recon/export-report", tags=["Deep Security Scan"])
async def export_html_report(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
):
    """
    Generate and return a professional HTML security assessment report.
    
    Accepts a payload containing:
    - target: The scanned target string
    - scan_result: The full deep scan result
    - analysis: The AI-generated analysis
    
    Returns a self-contained HTML document ready for download or printing.
    """
    gen = ReportGenerator()
    html_content = gen.generate_html_report(
        target=payload.get("target", "Unknown"),
        scan_result=payload.get("scan_result", {}),
        analysis=payload.get("analysis", {}),
    )
    return HTMLResponse(content=html_content)

# Finally, include v1_router into app
app.include_router(v1_router, prefix=settings.API_V1_STR)
