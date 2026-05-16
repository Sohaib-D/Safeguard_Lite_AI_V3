# Safeguard-AI Lite - Implementation-Accurate Project Details

Last inspected: 2026-05-12  
Workspace: `D:\4th Sem\Projects\PFAI_fixed`  
Purpose of this file: handoff context for a future AI coding model. This document describes the real repository as implemented. It does not describe an ideal target architecture unless clearly marked as upgrade guidance.

## 1. Project Overview

Safeguard-AI Lite is a Python security monitoring and defensive reconnaissance project with two major surfaces:

1. A FastAPI backend in `backend/api/main.py`.
2. A Streamlit dashboard in `frontend/App.py` plus separate Streamlit pages in `frontend/pages/`.

Confirmed current capabilities:

- JWT login and admin creation.
- CSV and JSON ML prediction endpoints.
- Streamlit upload, live prediction simulation, statistics, analytics, explainability, SOC dashboard, SOC assistant, active scanner, packet capture control, live monitor, and deep security scanner pages.
- Basic packet capture using Scapy.
- Lightweight heuristic live detection modules for connection spikes, DNS anomalies, and high traffic volume.
- Active reconnaissance scanner in `backend/network/active_scanner.py`.
- Deep scanner orchestrator in `backend/network/deep_scanner.py` using modular scanner files under `backend/network/scanner_modules/`.
- AI-assisted SOC and scan analysis through Groq-compatible chat-completion calls.
- HTML report generation through `backend/services/report_generator.py`.

Current limitations:

- Scanner architecture is only partially modular. There are scanner modules, but no shared typed scanner interface, no central finding schema model, and inconsistent evidence fields across modules.
- Deep scan schemas are dictionaries, not Pydantic models.
- Findings use mixed schemas. `http_scanner.py` and `cve_scanner.py` have recently moved toward evidence-driven fields, but `port_scanner.py`, `tls_scanner.py`, `dns_scanner.py`, and `webapp_scanner.py` still return thinner finding objects.
- Risk scoring is heuristic and can overstate risk. Open ports and missing headers are often converted into vulnerability-like conclusions.
- There are duplicate `/api/v1/recon/analyze-scan` and `/api/v1/recon/export-report` route definitions: one set in `backend/api/routes/recon.py`, another set later in `backend/api/main.py`.
- Some UI language implies stronger conclusions than the scanner evidence supports.
- Several files contain mojibake/encoding artifacts in comments and UI text.
- Docker Compose references build targets `backend` and `frontend`, but the current `Dockerfile` does not define named stages for those targets.

Defensive/passive-only scope:

- The project is intended for defensive monitoring, read-only reconnaissance, and reporting.
- It should not add payload injection, brute force, credential attacks, exploitation frameworks, malware, persistence, destructive testing, or DDoS functionality.
- Existing code has one serious violation of the desired defensive scope: `backend/network/scanner_modules/webapp_scanner.py` attempts WordPress default credential logins (`admin:admin`, `admin:password`). This should be removed or disabled in any professional defensive refactor.

## 1.1 Current Functional Status of App Tabs

Based on recent testing and user reports, the following is the status of the main App Tabs:

### ✅ Working Perfectly
*   **Login**: Authenticates users and generates JWT tokens correctly.
*   **Home**: Displays the welcome guide and basic metrics.
*   **Upload**: Successfully processes CSV files, returns predictions, and allows downloads.
*   **Live Predictions**: Correctly simulates traffic and displays live inference results.
*   **Explanations**: Successfully renders SHAP global importance and local row-level contributions (e.g., for "Inspect row 2").

### ⚠️ Working but Incomplete
*   **Statistics / Analytics**:
    *   **Problem**: Shows "0" for all metrics even after running predictions.
    *   **Why**: The `/predict` and `/upload` endpoints in `backend/api/main.py` perform calculations but do **not** save the results to the database (`ScanResult` table).
    *   **Fix**: Update `_perform_predictions` and `_predict_csv_bytes` in `main.py` to persist results to the database.

### ❌ Not Working / Broken
*   **SOC Operations Dashboard**:
    *   **Problem**: WebSocket Connection shows "Disconnected".
    *   **Why**: Likely a URL mismatch in `frontend/App.py`. The backend mounts the websocket at `/api/v1/ws/traffic`, but the frontend might be hitting an incorrect path depending on how `api_base_url` is configured.
    *   **Fix**: Standardize the `wsUrl` construction in `frontend/App.py` and ensure the backend `v1_router` correctly handles the handshake.
*   **SOC Analyst Assistant**:
    *   **Problem**: "Incident Timeline", "False Positive Analysis", etc., show "Not available".
    *   **Why**: The backend endpoint `/api/v1/ai/soc-analysis` in `main.py` returns a **hardcoded** response dictionary instead of using the AI's output.
    *   **Fix**: Update `ai_soc_analysis` in `backend/api/main.py` to parse the AI response from `AIService` into a structured JSON object containing all required fields.

## Tech stack:

- Backend: FastAPI, Uvicorn, Pydantic, SQLAlchemy, python-jose, bcrypt, httpx.
- Frontend: Streamlit, requests, pandas, matplotlib, Streamlit components.
- Database: SQLAlchemy with SQLite fallback or any `DATABASE_URL` supported by SQLAlchemy. PostgreSQL dependencies are installed.
- ML: scikit-learn, pandas, numpy, joblib, SHAP.
- Networking: Scapy, dnspython, python-whois, cryptography, sockets, ssl, httpx.
- AI: Groq API via direct httpx calls and `groq` dependency in `requirements.txt`.

Architecture summary:

```text
Streamlit UI
  frontend/App.py
  frontend/pages/*.py
       |
       | requests via frontend/api_client.py
       v
FastAPI app
  backend/api/main.py
  backend/api/routes/*.py
       |
       +-- ML prediction: backend/ml/model_loader.py, backend/ml/predictor.py
       +-- Active recon: backend/network/active_scanner.py
       +-- Deep recon: backend/network/deep_scanner.py -> scanner_modules/*.py
       +-- AI analysis: backend/services/ai_service.py, security_intelligence.py
       +-- HTML reports: backend/services/report_generator.py
       +-- Persistence: backend/db/*.py, backend/db/models.py
```

## 2. Repository Structure

Top-level files:

- `app.py`: single-process Streamlit entrypoint. Starts Uvicorn in a background thread on `127.0.0.1:8000`, sets `SAFEGUARD_API_BASE_URL`, imports `frontend.App`, then calls `main()`.
- `start.ps1`: Windows launcher. Creates `.venv`, installs requirements, then runs `python -m streamlit run app.py --server.port 8501 --server.address 127.0.0.1`.
- `requirements.txt`: pinned backend/frontend/ML dependencies plus unpinned `cryptography` and `aiofiles`.
- `README.md`: older project overview. Some paths are stale, e.g. lowercase `frontend/app.py`.
- `PROJECT_DETAIL.md`: existing singular detail file. It is partially stale and contains encoding artifacts.
- `PROJECT_DETAILS.md`: this file.
- `Dockerfile`: single builder/runtime image that runs Uvicorn only.
- `docker-compose.yml`: defines `database`, `backend`, `frontend`, but uses `target: backend` and `target: frontend` even though the Dockerfile has no such named stages.
- `pytest.ini`, `mypy.ini`, `.flake8`: test/lint configuration.

Important directories:

- `backend/api/`: FastAPI app and route modules.
- `backend/core/`: settings, logging, JWT/password helpers, custom exceptions.
- `backend/db/`: SQLAlchemy engine/session/models and a thin repository class.
- `backend/dependencies/`: auth dependency.
- `backend/ml/`: runtime model loader, predictor, SHAP helper.
- `backend/network/`: packet capture, active/deep scanners, live detection helpers.
- `backend/network/scanner_modules/`: port/TLS/HTTP/DNS/webapp/CVE scanners.
- `backend/schemas/`: Pydantic schemas, many of which are not actively used by the main prediction/deep scan routes.
- `backend/services/`: auth, alerts, AI, report generation, response engine, websocket manager, security intelligence.
- `frontend/`: Streamlit main app, API client, UI/CSS helpers, pages.
- `ml/`: offline preprocessing, training, explainability, optimization code.
- `scripts/`: dataset download, preprocessing, training CLIs.
- `tests/`: pytest tests for auth/API prediction, E2E prediction, preprocessing, training, packet capture, and live detection.
- `models/`: committed smoke model artifacts.
- `data/processed/`: committed smoke CSV data.

Execution entrypoints:

- Backend only: `uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload`.
- Frontend only: `streamlit run frontend/App.py`.
- Single process: `streamlit run app.py` or `.\start.ps1`.
- Tests: `pytest`.

## 3. Frontend Architecture

Framework: Streamlit.

Core files:

- `frontend/App.py`: main tabbed dashboard.
- `frontend/api_client.py`: synchronous requests client.
- `frontend/api_utils.py`: constructs `SafeguardAPIClient`, wraps errors, caches model info.
- `frontend/ui_components.py`: global CSS and UI rendering helpers. It is large and includes helper functions such as `apply_custom_css`, `render_sidebar`, `render_topbar`, `render_api_error`, `build_prediction_results_frame`, `render_first_row_explanation`, and scanner visual helpers.
- `frontend/scanner_styles.py`: CSS string for deep scanner page.
- `frontend/sample_data.py`: generates fake traffic records for live prediction simulation.

State management:

- Uses `st.session_state` directly.
- `frontend/App.py:init_state()` creates keys including `api_base_url`, `auth_token`, `auth_user`, `model_info_cache`, `latest_prediction_result`, `latest_upload_result`, `live_history`, `live_recent_events`, `live_alerts`, and `show_create_admin`.
- `frontend/pages/Deep_Security_Scanner.py:_init_state()` creates deep scanner specific keys including `deep_scan_result`, `deep_scan_analysis`, `deep_scan_target`, `deep_scan_running`, `deep_scan_history`, and counters.

API communication flow:

- `get_client()` in `frontend/api_utils.py` reads `SAFEGUARD_API_BASE_URL` or session `api_base_url`, defaulting to `http://127.0.0.1:8000`.
- `SafeguardAPIClient.__init__()` sets:
  - `raw_base_url = base_url.rstrip("/")`
  - `base_url = raw_base_url + "/api/v1"`
  - `health_url = raw_base_url + "/health"`
- Auth headers come from `st.session_state["auth_token"]` or constructor token.
- On HTTP 401, `_handle_response()` clears `auth_token` and returns `None` instead of raising.

Main app workflows in `frontend/App.py`:

- Login: `render_login()` calls `/api/v1/auth/login` through `client.login()`, or root `/auth/create-admin` through `client.create_admin()`.
- Upload: `render_upload()` previews CSV, calls `/api/v1/predict/csv`, stores `latest_prediction_result`, displays dataframe, allows CSV download.
- Live predictions: `render_live_predictions()` gets `raw_input_schema` from `/api/v1/model_info`, uses `generate_live_records()`, calls `/api/v1/predict/records`, updates live history.
- Statistics/analytics: call `/api/v1/monitoring/stats` through `client.stats` alias.
- SOC dashboard: embeds custom HTML/JS and connects to websocket URL `baseUrl.replace(/^http/, "ws") + "/ws/traffic"`. This means if `api_base_url` is `http://127.0.0.1:8000`, websocket path is `ws://127.0.0.1:8000/ws/traffic`, not `/api/v1/ws/traffic`. Backend websocket is mounted under `/api/v1/ws/traffic`, so this is a likely mismatch.
- SOC assistant: calls `/api/v1/ai/soc-analysis`.

Separate Streamlit pages:

- `frontend/pages/Active_Scanner.py`: calls `client.active_scan()` then optionally `client.analyze_vulnerability()`. Expects active scan schema: `dns`, `ports` as list, `ssl`, `http_headers`, `whois`, `security_configs`.
- `frontend/pages/Deep_Security_Scanner.py`: calls `client.deep_scan()`, `client.analyze_scan()`, then `client.export_report()`. Expects normalized deep scan schema from `backend/network/deep_scanner.py`.
- `frontend/pages/Capture_Control.py`: controls `/api/v1/capture/start`, `/api/v1/capture/stop`, `/api/v1/capture/stats`.
- `frontend/pages/Live_Monitor.py`: wraps capture control and shows alerts.
- `frontend/pages/Security_Center.py`: lists alerts, calls SOC analysis, acknowledges alerts. The "Block IP" flow is UI-only and does not call a backend blocking endpoint.

Known UI bugs and risks:

- Many pages contain emojis/mojibake such as `ðŸ...`, `âœ...`, and `â€”`. This appears to be encoding damage and may render poorly.
- `frontend/pages/Deep_Security_Scanner.py:_render_input()` captures `quick = st.checkbox(...)` but does not return it or pass it to `client.deep_scan()`. The backend supports `quick_scan`, but the UI ignores it.
- `SafeguardAPIClient.deep_scan()` sends only `{"target": target}`, relying on backend default `quick_scan=True`.
- `frontend/pages/Deep_Security_Scanner.py` warns "No WAF/CDN detected - origin IP may be exposed." This overstates evidence and should be softened.
- Active Scanner success text says no critical config vulnerabilities means protected against basic volumetric DDoS. That is not evidence-supported.
- SOC dashboard websocket path likely does not match backend prefix.

## 4. Backend Architecture

Framework: FastAPI with SQLAlchemy sessions and Pydantic schemas.

Main app: `backend/api/main.py`

- Configures logging via `configure_logging()`.
- Defines `lifespan()` startup:
  - verifies DB connection with `verify_connection()`;
  - creates tables with `Base.metadata.create_all(bind=engine)`;
  - seeds initial admin if `settings.ADMIN_USERNAME` does not exist.
- Adds CORS with `settings.ALLOWED_ORIGINS`.
- Adds global exception handler returning generic 500 JSON.
- Defines root `/`, `/health`, root compatibility aliases, and builds `v1_router`.
- Includes route modules:
  - `/api/v1/auth/*`
  - `/api/v1/alerts/*`
  - `/api/v1/monitoring/*`
  - `/api/v1/ws/traffic`
  - `/api/v1/recon/*`
- Also defines duplicate `/api/v1/recon/analyze-scan` and `/api/v1/recon/export-report` on the same `v1_router` after including `recon_module.router`.

Authentication:

- `backend/core/security.py` hashes passwords with bcrypt, signs JWTs with `settings.SECRET_KEY`, and stores UUID user ID in JWT `sub`.
- `backend/dependencies/auth.py:get_current_user()` decodes token, parses UUID, queries `User`, and rejects inactive users.
- Root `/auth/login` and `/api/v1/auth/login` both exist. Response models differ slightly:
  - root `/auth/create-admin` returns `TokenResponse` with token;
  - `/api/v1/auth/create-admin` returns `UserResponse` without token.

Prediction flow:

- `/api/v1/predict/records` and root `/predict` call `_perform_predictions(records)`.
- `/api/v1/predict/csv` and root `/upload` call `_predict_csv_bytes(content)`.
- `_perform_predictions()` and `_predict_csv_bytes()` instantiate `ModelLoader()` and `ThreatPredictor()` per request.
- Returned schema is not the full `backend/schemas/predict.py:PredictionResponse`. It omits `model_name`, `predicted_index`, `class_probabilities`, `top_contributions`, and `timestamp`.

Capture flow:

- Global `capture_engine = PacketCaptureEngine()` in `backend/api/main.py`.
- `/capture/start` starts `capture_engine.start_capture()` in a daemon thread.
- `/capture/stop` sets `is_running=False`.
- Stats endpoint currently returns mostly placeholders: `queue_size=0`, `flows_count=0`, `ip_count=0`.

Background task flow:

- `backend/api/routes/recon.py` defines `scan_jobs` and `background_deep_scan()`, but `/deep-scan` currently runs synchronously. There is no route that creates a `scan_id` and schedules `background_deep_scan()`. `/scan-status/{scan_id}` is effectively unused unless future code creates jobs.

Error handling:

- Deep scan route wraps scan failure into HTTP 500.
- `deep_scanner.safe_run()` wraps individual module errors into `{"error": ..., "failed": True, "findings": []}`.
- Global exception handler hides details from clients and logs stack traces.
- Many scanner modules swallow exceptions and return partial results.

## 5. Scanner Modules

### Active Scanner

File: `backend/network/active_scanner.py`  
Class: `ActiveScanner`

Public method:

- `scan_target(target: str) -> Dict[str, Any]`

Internal methods:

- `_is_ip(target)`
- `_resolve_and_ping(target)`
- `_scan_ports(ip)`
- `_get_port_context(port)`
- `_check_ssl(ip, domain=None)`
- `_get_http_headers(ip, port)`
- `_get_whois(domain)`
- `_evaluate_security(ports, headers, dns_info)`

Returned schema:

```python
{
  "target": str,
  "timestamp": iso_string,
  "dns": {"ip_address": str, "hostname": str | None, "MX_records": list, "TXT_records": list, "NS_records": list},
  "ports": [{"port": int, "service": str, "description": str, "banner": str | None, "vulnerability_context": str}],
  "ssl": dict | None,
  "http_headers": dict,
  "whois": dict | None,
  "latency_ms": float | None,
  "error": str | None,
  "security_configs": list[dict]
}
```

Weaknesses:

- `_get_http_headers()` requests by IP (`https://ip:443/`) rather than original host, so virtual hosts/CDNs may fail or return wrong headers.
- `_evaluate_security()` overstates risk:
  - SSH exposure becomes "Brute-Force Risk" even without auth evidence.
  - Missing WAF/CDN becomes "DDoS Vulnerability".
  - Missing CSP says XSS attacks are more likely to succeed.
- Port 8080 is labeled `HTTP-Proxy`, which can imply proxy exposure incorrectly.
- SSL check disables certificate verification to read certificate metadata; it separately records details but should label this clearly.

### Deep Scanner Orchestrator

File: `backend/network/deep_scanner.py`

Functions:

- `safe_run(coro, timeout=60.0)`
- `_clean_target(target)`
- `_compute_risk_grade(score)`
- `_fetch_whois(domain)`
- `_normalize_ports(raw)`
- `_normalize_ssl(raw)`
- `_normalize_headers(raw)`
- `_normalize_dns(raw)`
- `_normalize_technologies(raw_http, raw_webapp)`
- `_normalize_full_result(...)`
- `run_deep_scan(target, quick=True)`
- `run_scan_sync(target, quick=True)`
- `DeepScanner.scan(target, quick=True)`

Flow:

1. Clean target with `_clean_target()`.
2. Resolve IP using `socket.gethostbyname`.
3. Concurrently run:
   - `scan_ports(clean_target, quick=quick)` timeout 90s
   - `scan_tls(clean_target, port=443)`
   - `scan_http(target)`
   - `scan_dns(clean_target)`
   - `scan_webapp(target)`
   - `_fetch_whois(clean_target)` timeout 15s
4. Build CVE input from port banners, webapp CMS, and HTTP headers `server`, `x-powered-by`, `x-aspnet-version`.
5. Run `scan_cve(banners, software)` synchronously.
6. Normalize all raw module dicts into a frontend-oriented schema.

Returned top-level schema:

```python
{
  "target": str,
  "clean_target": str,
  "resolved_ip": str | None,
  "quick_scan": bool,
  "scan_timestamp": iso_string,
  "overall_risk_score": int,
  "risk_grade": "A+" | "B" | "C" | "D" | "F",
  "severity_counts": {"critical": int, "high": int, "medium": int, "low": int},
  "critical_findings": list[str],
  "total_findings": int,
  "ports": dict,
  "ssl": dict,
  "http_headers": dict,
  "dns": dict,
  "technologies": dict,
  "whois": dict,
  "cve_scan": dict,
  "raw_modules": {
    "port_scan": dict,
    "tls_scan": dict,
    "http_scan": dict,
    "dns_scan": dict,
    "webapp_scan": dict,
    "cve_scan": dict
  }
}
```

Risk formula:

- Counts findings by severity.
- `raw_score = critical*25 + high*15 + medium*8 + low*3`.
- `avg_confidence` defaults to `0.85`; if findings have `confidence_score`, uses average, otherwise missing confidence defaults to `0.7`.
- `risk_score = min(100, int(raw_score * avg_confidence))`.
- `_compute_risk_grade()` maps low score to `A+`, high score to `F`.

Fragility:

- `_normalize_headers()` marks missing CSP and HSTS as `Critical` risk level internally, even though scanner findings may be Medium.
- `_normalize_ssl()` loses certificate subject/issuer details; it returns placeholder `N/A`.
- `_normalize_dns()` sets `a_records` and `txt_records` to empty lists because `dns_scanner` does not return them.
- `_normalize_full_result()` adds additional structural findings, so findings are duplicated with scanner module findings.
- `risk_grade` can still emit `A+`, which conflicts with conservative reporting guidance if interpreted as "excellent/guaranteed".

### Port Scanner

File: `backend/network/scanner_modules/port_scanner.py`

Functions:

- `_scan_single_port(target, port, sem)`
- `scan_ports(target, quick=True)`

Inputs:

- `target`: hostname/IP.
- `quick=True`: scans `TOP_1000_PORTS` (1-1024 plus selected service ports). `quick=False` scans 1-65535.

Output:

```python
{
  "open_ports": [{"port": int, "service": str}],
  "critical_ports": list,
  "high_risk_ports": list,
  "banners": {port: banner},
  "total_open": int,
  "scan_duration_seconds": float,
  "findings": list[dict]
}
```

Dependencies: `asyncio`, `socket`, `time`.

Weaknesses:

- No `total_scanned` returned, but `_normalize_ports()` expects it and defaults to 1024.
- Banner read waits for services to speak first. HTTP banners usually remain empty.
- Open high-risk ports generate findings even without service configuration evidence. These should be observations, not vulnerabilities.
- `asyncio.gather()` creates many tasks. With `quick=False`, this creates 65,535 tasks and relies on semaphore for connection concurrency, which can be heavy on Windows.

### TLS Scanner

File: `backend/network/scanner_modules/tls_scanner.py`

Functions:

- `check_weak_cipher(cipher_name)`
- `check_deprecated_protocol(protocol)`
- `get_hsts_header(target, port)`
- `scan_tls(target, port=443)`

Output:

```python
{
  "is_valid": bool,
  "days_until_expiry": int,
  "protocol_version": str,
  "cipher_suite": str,
  "is_self_signed": bool,
  "domain_match": bool,
  "hsts_enabled": bool,
  "findings": list[dict],
  "has_error": bool,
  "error_message": str
}
```

Weaknesses:

- Uses `ssl.CERT_NONE` for the first TLS connection and performs a second verifying connection later.
- HSTS check uses raw TLS socket and basic header parsing.
- No OCSP stapling, certificate chain details, issuer/subject preservation, weak protocol enumeration, downgrade testing, or cipher suite enumeration.
- Findings lack consistent `confidence_score`, `evidence`, `detection_method`, `exploit_verified`, and `passive_only`.
- `check_deprecated_protocol()` treats `"TLSV1"` as deprecated, but Python `ssock.version()` usually returns `TLSv1`, `TLSv1.2`, etc.; current equality logic is mostly safe but should be tested.

### HTTP Scanner

File: `backend/network/scanner_modules/http_scanner.py`  
Current worktree status: modified relative to git. This is in-progress evidence-aware work.

Functions:

- `_check_sensitive_file(client, base_url, path, sem)`
- `scan_http(target)`

Output:

```python
{
  "headers_found": dict,
  "missing_security_headers": list[str],
  "cors_issues": list,
  "dangerous_methods": list,
  "sensitive_files_found": list,
  "cookie_issues": list[dict],
  "redirect_chain": list[str],
  "security_txt": str | None,
  "robots_txt": str | None,
  "findings": list[dict]
}
```

Checks:

- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy.
- Information disclosure: `Server`, `X-Powered-By`, `X-AspNet-Version`.
- Cookie flags: Secure, HttpOnly, SameSite.
- CORS probe with `Origin: https://evil.com`.
- OPTIONS allowed methods.
- Sensitive paths/resources including `.env`, `.git/HEAD`, backups, admin paths, robots.txt, sitemap.xml, security.txt.

Strengths:

- Most new findings include title, category, severity, confidence_score, description, evidence, detection_method, exploit_verified, passive_only, remediation, references.
- CSP/HSTS/CORS language is more conservative than previous code.

Weaknesses:

- Starts with `https://{target}` when no scheme is provided. It does not fall back to HTTP if HTTPS fails.
- Uses `verify=False`.
- Sensitive resource checks are active HTTP GETs against common paths. These are non-exploitative but not purely passive.
- Soft-404 detection is very weak.
- CORS reflected-origin test uses `evil.com`, which is a harmless header value but should be renamed to a neutral test origin for professionalism.

### DNS Scanner

File: `backend/network/scanner_modules/dns_scanner.py`

Functions:

- `extract_domain(target)`
- `_check_zone_transfer(domain, nameservers)`
- `_check_subdomain_takeover(domain, sub, resolver)`
- `scan_dns(target)`

Output:

```python
{
  "spf_status": "Missing" | "vulnerable" | "softfail" | "secure" | "neutral",
  "dkim_found": bool,
  "dmarc_policy": "Missing" | "p=none" | "p=quarantine" | "p=reject" | "other",
  "zone_transfer_possible": bool,
  "subdomains_found": [{"subdomain": str, "target": str}],
  "takeover_risks": list[str],
  "dnssec_enabled": bool,
  "findings": list[dict],
  "ns_records": list[str],
  "mx_records": list[str]
}
```

Weaknesses:

- Missing SPF/DMARC are reported as High and wording says "highly vulnerable to email spoofing"; should be softened to "lacks an email authentication control".
- DKIM check only tries common selectors, so absence is low confidence.
- DNSSEC missing is Low but language says DNS responses could theoretically be spoofed; should mention resolver/registrar context.
- Subdomain takeover detection is heuristic and limited.
- Findings do not use the standard evidence model.

### Webapp Scanner

File: `backend/network/scanner_modules/webapp_scanner.py`

Function:

- `scan_webapp(target)`

Output:

```python
{
  "cms_detected": str | None,
  "csrf_issues": list,
  "error_disclosure": bool,
  "dangerous_js_patterns": list,
  "mixed_content_found": bool,
  "findings": list[dict]
}
```

Checks:

- Forms without obvious CSRF token.
- Password field over HTTP.
- Cookie flags.
- Mixed content.
- Dangerous JS sink string search.
- Sensitive HTML comments.
- CMS detection for WordPress, Drupal, Joomla.
- Error disclosure using nonexistent page and `/?id='`.
- WordPress default credential login attempts.

Critical issue:

- The WordPress credential attempt is not acceptable for defensive/passive-only scope. Remove it or gate it behind an explicit disabled-by-default setting with strong warnings. The requested future platform should not include credential attacks.

False-positive risks:

- CSRF detection is regex-based and cannot know framework protections.
- Dangerous JS sinks are raw string searches and do not prove XSS.
- Error disclosure probe includes a quote in URL parameter; this is close to payload testing and should be reviewed for legal/ethical posture.
- Findings lack standardized fields.

### CVE Scanner

File: `backend/network/scanner_modules/cve_scanner.py`  
Current worktree status: modified relative to git. This is in-progress evidence-aware work.

Functions:

- `parse_version_tuple(v)`
- `version_matches(detected, rule)`
- `check_eol(software, version)`
- `extract_software_info(texts)`
- `get_severity_from_cvss(score)`
- `scan_cve(banners, software_detected)`

Output:

```python
{
  "matched_cves": [{"software": str, "version": str, "cve": str, "cvss": float, "desc": str}],
  "eol_software": list[str],
  "total_critical_cves": int,
  "total_high_cves": int,
  "findings": list[dict]
}
```

Strengths:

- New wording says "Potentially Affected" and explicitly says exploitability is not verified.
- Uses `confidence_score=0.70` for banner-based detection.

Weaknesses:

- Local `CVE_DB` is tiny, hard-coded, and likely stale.
- Version extraction is regex-based and may misparse banners.
- CVE matching is banner correlation only; should never be treated as confirmed vulnerability.
- No disclosure date or exploit maturity.

### Technology Fingerprinting

There is no dedicated scanner module named technology scanner. Current technology section is built in `deep_scanner._normalize_technologies(raw_http, raw_webapp)` from:

- HTTP headers `Server`, `X-Powered-By`.
- Webapp CMS detection.
- CDN/WAF hints from headers such as `cf-ray`, Cloudflare strings, `x-cdn`, `x-cache`, `x-sucuri`.

Weaknesses:

- No Wappalyzer-style signatures.
- No JavaScript library fingerprinting beyond webapp sink searches.
- WAF/CDN detection is incomplete and can be false negative.
- UI currently interprets missing WAF too strongly.

### WHOIS/Reputation Logic

WHOIS exists in two places:

- `ActiveScanner._get_whois()`
- `deep_scanner._fetch_whois()`

There is no external reputation intelligence beyond WHOIS and simple DNS/technology heuristics.

### Risk Scoring Engine

There is no separate engine module. Risk is computed in:

- `backend/network/deep_scanner.py:_normalize_full_result()`
- `backend/services/security_intelligence.py:_build_fallback_analysis()`

The AI path can generate its own risk analysis from prompts, but fallback analysis is deterministic.

## 6. Data Schemas

Authentication:

- `/api/v1/auth/login` request: `{"username": str, "password": str}`
- `/api/v1/auth/login` response: `{"access_token": str, "token_type": "bearer", "username": str}`
- root `/auth/create-admin` response includes token, expires_in, username, is_admin.
- `/api/v1/auth/create-admin` response returns User ORM fields through `UserResponse`, not token.

Prediction actual response from `_perform_predictions()`:

```python
{
  "predictions": [
    {
      "row_index": int,
      "predicted_label": str,
      "confidence": float,
      "recommendation_severity": "Alert" | "Normal",
      "recommendations": list[str]
    }
  ],
  "summary": {
    "prediction_count": int,
    "labels": dict[str, int],
    "recommended_actions": list[str]
  }
}
```

Prediction Pydantic schema in `backend/schemas/predict.py` expects more fields:

- `PredictionResponse.model_name`
- `PredictionItem.predicted_index`
- `PredictionItem.class_probabilities`
- `PredictionItem.top_contributions`
- `PredictionResponse.timestamp`

This is a schema mismatch. Existing tests only assert the actual simplified shape, so do not change it without updating frontend and tests.

Deep scan frontend expected schema:

- `frontend/pages/Deep_Security_Scanner.py` expects:
  - `overall_risk_score`, `risk_grade`, `resolved_ip`, `ports.open_count`, `ports.open_ports`, `ssl.certificate.is_valid`, `ssl.protocol.version`, `ssl.cipher.name`, `http_headers.headers`, `http_headers.cors_issues`, `http_headers.cookie_issues`, `http_headers.sensitive_files`, `technologies.web_server`, `technologies.backend_framework`, `technologies.cms`, `technologies.cdn`, `technologies.waf_detected`, `dns.spf_status`, `dns.dkim_found`, `dns.dmarc_policy`, `dns.zone_transfer.successful`, `whois.expiry_date`, and analysis fields.

Analysis expected schema:

```python
{
  "executive_summary": str,
  "technical_summary": str,
  "risk_level": str,
  "attack_surface_score": int,
  "vulnerabilities": [
    {
      "id": str,
      "title": str,
      "category": str,
      "severity": str,
      "cvss_score": float,
      "description": str,
      "technical_detail": str,
      "affected_component": str,
      "exploitation_scenario": str,
      "remediation": str,
      "references": list[str]
    }
  ],
  "compliance_gaps": {"owasp_top_10": list, "pci_dss": str, "gdpr_relevant": str, "iso27001_gaps": list},
  "attack_vectors": [{"vector": str, "likelihood": str, "impact": str, "description": str}],
  "security_posture_breakdown": {
    "network_security": int,
    "application_security": int,
    "ssl_tls_hygiene": int,
    "header_security": int,
    "information_disclosure": int
  },
  "quick_wins": list[str],
  "remediation_roadmap": [{"priority": int, "action": str, "effort": str, "impact": str}]
}
```

Finding schema status:

- Desired future schema should include `title`, `category`, `severity`, `confidence_score`, `evidence`, `reasoning`, `detection_method`, `affected_asset`, `exploit_verified`, `passive_only`, `remediation`, `references`, and CWE/OWASP/CVE mapping.
- Current actual scanner findings are inconsistent. Only `http_scanner.py` and `cve_scanner.py` mostly approach the desired shape.

Export/report schema:

- `client.export_report(target, scan_result, analysis)` sends JSON to `/api/v1/recon/export-report`.
- Backend returns raw HTML bytes (`text/html`) using `HTMLResponse`.
- `ReportGenerator.generate_html_report(target, scan_result, analysis)` expects deep scan normalized schema plus analysis schema.

## 7. Current Bugs & Problems

HTML report rendering bug:

- `backend/services/report_generator.py` currently returns a full HTML document with `<!DOCTYPE html>`, `<html>`, `<head>`, `<style>`, and `<body>`. This is correct in the inspected code.
- If CSS renders as plain text in browser/download, likely causes are frontend download handling, an old cached report, duplicate route confusion, or malformed HTML in the truncated/uninspected section. Verify by calling `/api/v1/recon/export-report` directly and opening the downloaded bytes.
- Current `ReportGenerator` imports Google Fonts inside CSS. That may break standalone/offline compatibility.

Schema mismatches:

- Prediction actual response does not match `backend/schemas/predict.py`.
- `frontend/pages/Deep_Security_Scanner.py` expects normalized deep scan schema, while `SecurityIntelligence._build_fallback_analysis()` also references legacy/nonexistent keys such as `content_analysis`, `robots`, and `security_txt`.
- `LogService` imports `session_scope` from `backend.db.session`, but only `transaction_scope` exists. Also `PostgresStore` does not implement `log_activity()` or `get_stats()`. This service appears broken if used.
- Docker Compose build targets do not exist in Dockerfile.
- SOC websocket frontend path likely omits `/api/v1`.

False-positive logic:

- Active scanner treats exposed SSH/RDP/FTP/Telnet too strongly.
- Active scanner treats missing CDN/WAF as DDoS vulnerability.
- DNS scanner treats missing SPF/DMARC as high vulnerability rather than control gap.
- Webapp scanner treats regex-observed forms, JavaScript sinks, and comments as vulnerabilities without confidence qualifiers.
- SecurityIntelligence fallback uses terms like "attacker could exploit" and "vulnerable" based on passive observations.

TLS/SNI problems:

- Active scanner improved SNI by passing original domain to `_check_ssl()`.
- Deep TLS scanner uses `server_hostname=target`, where `target` is cleaned host. This should work for domains but not IPs.
- HTTP scanner defaults to HTTPS and does not retry HTTP.

Async/concurrency issues:

- `port_scanner.scan_ports(quick=False)` creates 65k tasks. This can strain Windows and event loop memory.
- `recon.scan_jobs` is in-memory and unused for actual background scan starts.
- `PacketCaptureEngine.start_capture()` blocks inside sniff and is run in a thread; stop uses Scapy `stop_filter`, which only evaluates on packet arrival, so stop may appear delayed when no packets arrive.
- Websocket manager is not integrated with packet capture; packet callback has broadcast code commented out.

Windows-specific issues:

- Scapy sniffing usually needs admin/Npcap on Windows.
- Full port scans may hit ephemeral port/socket limits.
- Many files have line-ending warnings (`LF will be replaced by CRLF`) and mojibake.

Safest fix strategy:

- First stabilize schemas and tests before expanding scanner capability.
- Add compatibility fields rather than renaming existing keys.
- Keep `/api/v1` routes and root compatibility aliases.
- Do not alter prediction response shape unless frontend and tests are changed together.

## 8. Reporting System

Report generation:

- API route: `/api/v1/recon/export-report`.
- Client method: `SafeguardAPIClient.export_report()`.
- Backend class: `backend/services/report_generator.py:ReportGenerator`.
- Main method: `generate_html_report(target, scan_result, analysis)`.

HTML pipeline:

1. Frontend deep scanner stores `scan_result` and `analysis`.
2. User clicks "Download HTML Report".
3. Frontend posts target, scan_result, analysis.
4. Backend builds HTML sections:
   - cover page
   - executive summary
   - risk gauge
   - security posture
   - vulnerability table
   - compliance
   - attack vectors
   - remediation roadmap
   - quick wins
   - footer/disclaimer
5. Frontend exposes returned bytes through `st.download_button(..., mime="text/html")`.

Current report risks:

- Analysis-driven report can omit raw evidence snippets from scanner findings.
- Footer disclaimer is close to desired but not exact. Required future disclaimer should be exactly:
  "This assessment was performed using non-invasive defensive reconnaissance techniques and does not verify exploitability or guarantee the absence of vulnerabilities."
- Report uses "Identified Vulnerabilities" even when findings are passive observations.
- Report uses grades and risk score that can be interpreted too strongly.
- External font import hurts standalone export.

## 9. Risk Engine Analysis

Current deep scan score:

- Pure heuristic by severity counts and average confidence.
- No explicit exposure context beyond finding severity.
- No explicit mitigation weighting except what individual scanner findings imply.
- No separate confidence tier labels.
- Open ports, TLS errors, and missing headers can materially increase score.

Why scores may be misleading:

- Scanner findings are not normalized by quality or evidence type.
- DNS and webapp findings lacking `confidence_score` default to 0.7 in average confidence.
- Missing WAF/CDN is not a direct vulnerability.
- Missing CSP/HSTS is a weakness, not proof of exploitable XSS/MITM.
- Passive banner CVE correlation is not exploit verification.
- `risk_grade="A+"` may imply stronger assurance than a passive scan can provide.

Recommended future risk language:

- Use posture labels such as "Minimal externally observable risk", "Moderate exposure", "Elevated attack surface", or "Strong edge-layer security posture".
- Avoid "secure", "fully protected", "verified vulnerable", and "A+ guaranteed".

## 10. Security Philosophy

The system must remain defensive, read-only, and non-exploitative.

Hard rules for future changes:

- Do not add brute forcing, credential attacks, exploit payloads, malware, persistence, destructive tests, or DDoS functionality.
- Do not imply guaranteed security, verified exploitability, successful compromise, or 100% secure conclusions.
- Treat all passive observations as observations unless there is explicit validation.
- CVE matching from banners must be "potentially affected" only.
- Open ports are exposure observations, not vulnerabilities by themselves.
- Missing controls are hardening gaps, not proof of compromise.

## 11. Upgrade Guidance for Claude Opus 4.6

Safest refactor order:

1. Add tests that freeze current API and frontend schemas:
   - prediction response shape;
   - active scan response shape;
   - deep scan normalized response shape;
   - report export starts with `<!DOCTYPE html>` and contains one `<style>` block inside `<head>`.
2. Introduce shared typed schemas for findings and scan sections in new files. Do not remove old keys yet.
3. Normalize all scanner findings into a central evidence model while preserving existing output fields.
4. Remove or disable non-defensive logic in `webapp_scanner.py`, especially WordPress credential attempts.
5. Fix report language and disclaimer.
6. Reduce false positives in ActiveScanner and SecurityIntelligence fallback.
7. Split risk scoring into a dedicated module but keep `overall_risk_score`, `risk_grade`, and `severity_counts` for compatibility.
8. Add async concurrency controls and bounded task batching for full port scans.
9. Improve TLS/HTTP/DNS modules incrementally.
10. Only then consider broader plugin-style scanner architecture.

Highest-risk files:

- `backend/api/main.py`: central app, duplicated route definitions, prediction endpoints, capture globals.
- `backend/network/deep_scanner.py`: normalized schema consumed by UI and AI analysis.
- `frontend/pages/Deep_Security_Scanner.py`: tightly coupled to deep scan schema.
- `backend/services/security_intelligence.py`: converts scan results into vulnerabilities and report data.
- `backend/services/report_generator.py`: report rendering.
- `frontend/api_client.py`: route paths and response parsing.
- `backend/network/scanner_modules/webapp_scanner.py`: contains ethically risky/default credential logic.

Safest modules to improve first:

- `backend/network/scanner_modules/http_scanner.py`: already partially evidence-aware.
- `backend/network/scanner_modules/cve_scanner.py`: already partially conservative.
- `backend/services/report_generator.py`: can improve language and HTML validation with low runtime risk.
- Tests under `tests/`: add schema/export tests before refactors.

Schema stabilization strategy:

- Create additive normalized schemas, e.g. `Finding`, `Evidence`, `ScanMetadata`, but keep current dict keys.
- Add `findings_normalized` alongside old `findings` if needed.
- Avoid renaming `http_headers`, `ssl`, `ports`, `technologies`, `whois`, `severity_counts`, and `critical_findings` until frontend is migrated.
- Add Pydantic validation at route boundary after compatibility tests pass.

Regression prevention:

- Run `pytest` before and after every change.
- Add tests for:
  - `/api/v1/recon/deep-scan` with monkeypatched scanner modules;
  - `/api/v1/recon/export-report`;
  - frontend client path construction;
  - report HTML validity;
  - no offensive scanner behavior.
- Keep root compatibility aliases `/predict`, `/upload`, `/auth/login`, `/auth/create-admin`.

## 12. Testing & Validation

Run project:

```powershell
.\start.ps1
```

Run backend:

```powershell
uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Run frontend:

```powershell
streamlit run frontend/App.py
```

Run tests:

```powershell
pytest
```

Focused tests:

```powershell
pytest tests/test_api.py tests/test_e2e.py -q
pytest tests/test_packet_capture.py tests/test_detection_engine.py -q
pytest tests/test_preprocessing.py tests/test_training.py -q
```

Validate exports:

- Authenticate.
- Run a deep scan.
- Call `/api/v1/recon/export-report`.
- Assert response headers indicate HTML, content starts with `<!DOCTYPE html>`, CSS is inside `<style>` in `<head>`, and body contains the disclaimer.
- Open downloaded HTML in a browser and print preview.

Missing tests:

- No tests for scanner modules under `backend/network/scanner_modules/`.
- No tests for deep scan normalization.
- No tests for report generator.
- No tests for `SecurityIntelligence` fallback.
- No tests for frontend deep scanner schema expectations.
- No tests for Docker Compose validity.

Recommended immediate tests:

- `test_deep_scan_schema_with_mocked_modules`
- `test_report_generator_returns_valid_document`
- `test_http_scanner_findings_include_evidence_fields`
- `test_cve_scanner_uses_potentially_affected_language`
- `test_webapp_scanner_does_not_attempt_credentials`
- `test_soc_websocket_url_matches_backend_prefix`

## Critical Architectural Risks

- Dict-based scan/result schemas make frontend/backend mismatches easy.
- Duplicate recon routes can obscure which handler is active.
- AI prompt/fallback may overstate passive findings.
- Webapp scanner contains credential-attempt logic contrary to defensive-only scope.
- Risk scoring is heuristic and not isolated.
- Docker Compose currently does not match Dockerfile stages.

## High Regression Risk Files

- `backend/api/main.py`
- `backend/api/routes/recon.py`
- `backend/network/deep_scanner.py`
- `backend/services/security_intelligence.py`
- `backend/services/report_generator.py`
- `frontend/api_client.py`
- `frontend/pages/Deep_Security_Scanner.py`
- `frontend/App.py`

## Most Fragile Components

- Deep scan normalized schema.
- Analysis/report schema between `SecurityIntelligence`, `ReportGenerator`, and Streamlit.
- Prediction response schema, because tests and UI rely on simplified dict output while Pydantic schemas describe a richer shape.
- Packet capture stop behavior.
- Websocket path/prefix.
- Docker deployment.

## Safest Refactor Sequence

1. Freeze current behavior with tests.
2. Add central finding schema and adapters, not replacements.
3. Normalize scanner findings.
4. Remove offensive/non-defensive checks.
5. Soften false-positive language and risk wording.
6. Fix HTML report/disclaimer/offline CSS.
7. Extract risk engine with compatibility output.
8. Add typed scanner interfaces and plugin-style registration.
9. Improve async execution/concurrency controls.
10. Expand scanner coverage only after schema and tests are stable.

## Recommended Immediate Fixes

- Remove WordPress default credential attempts from `webapp_scanner.py`.
- Fix SOC websocket URL to include `/api/v1/ws/traffic` or mount websocket at root too.
- Resolve duplicate `/recon/analyze-scan` and `/recon/export-report` route definitions.
- Add exact required passive reconnaissance disclaimer to reports.
- Rename risk UI labels away from "vulnerabilities" where findings are observations.
- Make ActiveScanner `_evaluate_security()` conservative.
- Add report HTML validation test.
- Fix `LogService` import/use of nonexistent `session_scope` and nonexistent `PostgresStore` methods if that service is needed.

## Recommended Long-Term Improvements

- Introduce typed schemas for all scan sections and findings.
- Build a central Reporting and Evidence Engine.
- Build a dedicated Risk Correlation Engine.
- Add scanner plugin interface with shared timeout/retry/concurrency handling.
- Add confidence levels: Confirmed, High Confidence, Moderate Confidence, Heuristic Observation, Informational.
- Add evidence caching and scan IDs.
- Add structured logs per scan module.
- Add DNS CAA, richer DNSSEC, IPv6, HTTP/2, OCSP stapling, and certificate chain analysis.
- Replace hard-coded CVE matching with a maintained, cacheable advisory source and strict confidence gates.
- Add integration tests for exports and frontend schema rendering.
