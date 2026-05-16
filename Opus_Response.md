# Safeguard-AI Lite: Complete Project Context & Details

This document contains the complete context, architecture, technical stack, and operational details of the **Safeguard-AI Lite** project. It is designed to be provided to any LLM or AI model as a single source of truth to fully understand the project before making code changes, debugging, or adding new features.

---

## 1. Project Overview
**Safeguard-AI Lite** is a professional, high-performance Cybersecurity Analyst Console designed for lightweight intrusion detection, network monitoring, and safe reconnaissance. It combines a FastAPI backend, a Streamlit-based analyst dashboard, classical tabular ML models for threat prediction, SHAP for explainability, and AI-driven SOC (Security Operations Center) assistance.

It operates on a "Human-in-the-Loop" philosophy, providing actionable intelligence and automated threat triage without performing unauthorized offensive actions.

---

## 2. Technology Stack & Architecture

### **Backend (API & Services Layer)**
- **Framework:** FastAPI (Python)
- **Server:** Uvicorn (async server)
- **Database:** PostgreSQL (Cloud-hosted via Supabase) or local SQLite. ORM handled via SQLAlchemy 2.0 with connection pooling.
- **Authentication:** JWT (JSON Web Tokens) with Bearer Token authorization. Bcrypt for password hashing.
- **Networking & Reconnaissance:** Scapy, PyShark, `dnspython`, `python-whois` for packet capture, active scanning, and deep security scanning.
- **AI Integration:** Groq SDK (`llama-3.1-70b-versatile` model) used for real-time SOC analyst assistance, threat analysis, and vulnerability assessment.

### **Frontend (Analyst Dashboard)**
- **Framework:** Streamlit
- **Design System:** Custom Glassmorphic CSS (Minimalist, dark-mode focused UI elements in `ui_components.py`).
- **Data Visualization:** Matplotlib and Pandas for traffic analytics and threat mix charts.
- **Navigation:** Multi-page layout with a main dashboard (`App.py`) and various functional views.

### **Machine Learning (ML) Engine**
- **Library:** Scikit-learn (RandomForest, Logistic Regression, etc.).
- **Interpretability:** SHAP (SHapley Additive exPlanations) for feature-level "Explainable AI".
- **Models:** Multiclass intrusion detection models predicting labels like `Normal`, `DDoS`, `Brute Force`, `XSS`, `SQL Injection`.
- **Optimization:** Features include optional pruning, quantization, and JAX inference metadata.

---

## 3. Detailed Core Features

### **A. Authentication & User Management**
- Secure JWT-based login (`/auth/login`).
- Admin user seeding on startup if no admin exists (`/auth/create-admin`).
- Endpoints are protected by `get_current_user` dependency.

### **B. Network Reconnaissance & Deep Scanning**
- **Active Scanner:** Performs basic network scans.
- **Deep Scanner:** Performs deeper analysis (open ports, HTTP headers, TLS configs, etc.).
- **Report Generation:** Generates professional HTML/PDF-ready security assessment reports based on scan results.

### **C. AI-Powered SOC Assistant**
- Integrates with Groq API.
- **SOC Analysis:** AI analyzes suspicious network activity payloads and provides risk assessments and remediation recommendations.
- **Vulnerability Analysis:** AI acts as a principal auditor, strictly analyzing open ports (e.g., 21, 23, 80) and configs to produce JSON-structured vulnerability reports.

### **D. ML Threat Detection Pipeline**
- Supports uploading CSV logs of network traffic or sending JSON arrays of network records.
- ML models evaluate records and return predicted labels with confidence scores.
- Threat summaries include automated recommendations (e.g., "Review logs", "Monitor IPs").

### **E. Live Packet Capture**
- Multithreaded packet capture engine using Scapy.
- Tracks active interfaces, flows, and basic capture statistics.

---

## 4. Comprehensive Directory Structure

```text
PFAI_fixed/
├── .env                    # Secret keys, DB URLs, and Admin credentials
├── docker-compose.yml      # Docker deployment config (backend, frontend, db)
├── requirements.txt        # Python dependencies
├── backend/                # FastAPI Backend Application
│   ├── api/                
│   │   ├── main.py         # FastAPI application entry point and root routers
│   │   └── routes/         # Feature-specific API routers (auth, alerts, monitoring)
│   ├── core/               
│   │   ├── config.py       # Pydantic Settings (ENV loading)
│   │   ├── logging_config.py # Structured logging configuration
│   │   └── security.py     # JWT token generation, password hashing
│   ├── db/                 
│   │   ├── database.py     # SQLAlchemy engine, session maker, base
│   │   ├── models.py       # SQLAlchemy ORM Models (User, DetectionAlert, ScanResult)
│   │   ├── session.py      # Dependency injection for DB sessions
│   │   └── postgres_store.py / sqlite_store.py # Data access layers
│   ├── dependencies/       
│   │   └── auth.py         # get_current_user FastAPI dependency
│   ├── ml/                 # ML prediction logic, model loaders, predictor classes
│   ├── network/            
│   │   ├── active_scanner.py # Basic recon scanning logic
│   │   ├── deep_scanner.py   # In-depth network recon
│   │   └── packet_capture.py # Background thread packet capture engine
│   ├── schemas/            # Pydantic validation models (UserCreate, TokenResponse)
│   └── services/           
│       ├── ai_service.py   # Groq SDK wrapper for LLM requests
│       ├── auth_service.py # Authentication business logic
│       ├── report_generator.py # HTML report generation for deep scans
│       └── security_intelligence.py # AI security assessment formatting
├── frontend/               # Streamlit Frontend Application
│   ├── App.py              # Main Streamlit entry point
│   ├── api_client.py       # Abstraction layer for making HTTP calls to Backend
│   ├── api_utils.py        # Shared API utilities
│   ├── sample_data.py      # Generates fake traffic for testing
│   ├── ui_components.py    # Custom Streamlit UI elements (Glassmorphism CSS)
│   └── pages/              # Standalone Streamlit sidebar pages
├── ml/                     # Model Training & Preprocessing (Offline)
│   ├── preprocessing.py    # Data cleaning, encoding, PCA
│   ├── training.py         # Model evaluation and export (.pkl)
│   ├── explainability.py   # SHAP integration
│   └── optimization.py     # Feature pruning, quantization
├── models/                 # Saved models and SHAP artifacts (e.g., best_model.pkl)
├── scripts/                # Utility scripts for training and preprocessing
└── tests/                  # Pytest unit and integration tests
```

---

## 5. Backend API Endpoints (FastAPI)

### Authentication
- `POST /api/v1/auth/create-admin`: Seed admin user.
- `POST /api/v1/auth/login`: Authenticate and return JWT Bearer token.
- `POST /auth/login` (Root alias)

### Network Capture
- `POST /api/v1/capture/start`: Start background packet capture.
- `POST /api/v1/capture/stop`: Stop packet capture.
- `GET /api/v1/capture/stats`: Get capture stats (interface, running state).

### Reconnaissance & Deep Scanning
- `POST /api/v1/recon/scan`: Basic active target scan.
- `POST /api/v1/recon/deep-scan`: Comprehensive scan of a target.
- `POST /api/v1/recon/analyze-scan`: Send scan results to Groq AI for security intelligence analysis.
- `POST /api/v1/recon/export-report`: Generates HTML security report of a deep scan.

### AI SOC & Vulnerability
- `POST /api/v1/ai/soc-analysis`: AI review of suspicious activity.
- `POST /api/v1/ai/vulnerability-analysis`: AI strict audit of open ports/headers.

### ML Predictions
- `POST /api/v1/predict/records` or `POST /predict`: Predict on JSON network flow records.
- `POST /api/v1/predict/csv` or `POST /upload`: Upload a CSV file and get ML threat predictions.

### System Info
- `GET /health`: Basic health check.
- `GET /model_info`: Details of the active ML model (labels, feature count).
- `GET /stats`: DB summary of total alerts, scans, and predictions.

---

## 6. Database Schema (SQLAlchemy)
The system tracks persistent data via `backend.db.models`:
- **User:** `id`, `username`, `hashed_password`, `is_admin`, `is_active`.
- **DetectionAlert:** `id`, `timestamp`, `source_ip`, `destination_ip`, `threat_type`, `severity`, `status`, `notes`.
- **ScanResult:** `id`, `timestamp`, `predicted_label`, `confidence`, `features_json`.
- **ActivityLog:** Audit trails of user actions or system events.

---

## 7. Environment Variables (`.env`)

```env
# Backend / System
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=False
ALLOWED_ORIGINS=["http://localhost:8501"]

# Database
DATABASE_URL=postgresql://user:password@host:port/dbname (For Supabase/PostgreSQL)
# Or use sqlite fallback for local dev: sqlite:///./data/safeguard_ai.db

# Security
JWT_SECRET_KEY=your_super_secret_jwt_key
ADMIN_USERNAME=admin_user
ADMIN_PASSWORD=StrongPass123

# AI Integration
GROQ_API_KEY=your_groq_api_key_here

# ML
MODEL_BUNDLE_PATH=models/trained_multiclass_smoke/best_model.pkl
```

---

## 8. Development & Deployment

### Local Execution
1. Install dependencies: `pip install -r requirements.txt`
2. Run Backend: `uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload`
3. Run Frontend: `streamlit run frontend/App.py`

### Docker Deployment
The `docker-compose.yml` configures three services:
- **database**: Alpine-based simple volume for SQLite fallback (can be swapped for Postgres).
- **backend**: Builds the FastAPI app. Passes networking capabilities (`NET_RAW`, `NET_ADMIN`) needed for Scapy.
- **frontend**: Builds the Streamlit app.

Run with: `docker compose up --build`

---

## Guidelines for AI Models Making Changes
- **Framework Conformity:** Respect FastAPI patterns (routers, Pydantic schemas, dependency injection) and Streamlit component structures.
- **Security:** Maintain the integrity of JWT authentication. Do not expose secret keys.
- **Modularity:** Ensure new services are placed in `backend/services/` and database logic remains in `backend/db/`.
- **UI Consistency:** Use existing Streamlit components in `frontend/ui_components.py` for uniform glassmorphic aesthetics.
- **Imports:** Be mindful of Python relative and absolute imports (e.g., always `from backend.core.config import ...`).
