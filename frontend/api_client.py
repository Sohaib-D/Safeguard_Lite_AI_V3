from __future__ import annotations
from typing import Any
import requests
import streamlit as st

def get_auth_headers() -> dict[str, str]:
    token = st.session_state.get("auth_token", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

class APIClientError(RuntimeError):
    def __init__(self, message: str, errors: list[str] | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.errors = errors or []
        self.status_code = status_code

class SafeguardAPIClient:
    """Production-grade client for the Safeguard-AI v1 API."""

    def __init__(self, base_url: str, token: str | None = None):
        self.raw_base_url = base_url.rstrip("/")
        self.base_url = f"{self.raw_base_url}/api/v1"
        self.health_url = f"{self.raw_base_url}/health"
        self.token = token

    @property
    def stats(self):
        """Alias for get_stats to maintain compatibility with existing frontend code."""
        return self.get_stats

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        headers.update(get_auth_headers())
        if "Authorization" not in headers and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _handle_response(self, response: requests.Response) -> Any:
        try:
            payload = response.json()
        except ValueError:
            payload = {"detail": response.text or "Unexpected server error"}

        if response.status_code == 401:
            st.session_state["auth_token"] = None
            return None

        if response.ok:
            return payload

        raise APIClientError(
            message=str(payload.get("detail", "Request failed")),
            errors=list(payload.get("errors", [])),
            status_code=response.status_code
        )

    def health(self) -> dict[str, Any]:
        response = requests.get(self.health_url, timeout=10)
        return self._handle_response(response)

    def login(self, username: str, password: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password},
            timeout=15
        )
        return self._handle_response(response)

    def model_info(self) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/model_info",
            headers=self._headers(),
            timeout=15
        )
        return self._handle_response(response)

    def get_alerts(self, limit: int = 50) -> list[dict]:
        response = requests.get(
            f"{self.base_url}/alerts/",
            headers=self._headers(),
            params={"limit": limit},
            timeout=15
        )
        return self._handle_response(response)

    def get_stats(self) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/monitoring/stats",
            headers=self._headers(),
            timeout=15
        )
        return self._handle_response(response)

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = None, comment: str = None) -> dict:
        response = requests.post(
            f"{self.base_url}/alerts/{alert_id}/acknowledge",
            headers=self._headers(),
            json={"acknowledged_by": acknowledged_by or "analyst", "comment": comment or ""},
            timeout=15
        )
        return self._handle_response(response)

    def active_scan(self, target: str) -> dict:
        response = requests.post(
            f"{self.base_url}/recon/scan",
            headers=self._headers(),
            json={"target": target},
            timeout=60
        )
        return self._handle_response(response)

    def analyze_soc(self, payload: dict) -> dict:
        response = requests.post(
            f"{self.base_url}/ai/soc-analysis",
            headers=self._headers(),
            json=payload,
            timeout=30
        )
        return self._handle_response(response)

    def analyze_vulnerability(self, payload: dict) -> dict:
        response = requests.post(
            f"{self.base_url}/ai/vulnerability-analysis",
            headers=self._headers(),
            json=payload,
            timeout=30
        )
        return self._handle_response(response)

    def get_capture_stats(self) -> dict:
        response = requests.get(
            f"{self.base_url}/capture/stats",
            headers=self._headers(),
            timeout=10
        )
        return self._handle_response(response)

    def start_capture(self, interface: str = None) -> dict:
        response = requests.post(
            f"{self.base_url}/capture/start",
            headers=self._headers(),
            json={"interface": interface},
            timeout=30
        )
        return self._handle_response(response)

    def stop_capture(self) -> dict:
        response = requests.post(
            f"{self.base_url}/capture/stop",
            headers=self._headers(),
            timeout=30
        )
        return self._handle_response(response)

    def predict_records(self, records: list[dict], include_explanations: bool = False, explanation_top_k: int = 5) -> dict:
        response = requests.post(
            f"{self.base_url}/predict/records",
            headers=self._headers(),
            json={
                "records": records,
                "include_explanations": include_explanations,
                "explanation_top_k": explanation_top_k
            },
            timeout=30
        )
        return self._handle_response(response)

    def create_admin(self, username: str, password: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.raw_base_url}/auth/create-admin",
            json={"username": username, "password": password},
            timeout=15
        )
        return self._handle_response(response)

    def predict_csv(self, file_name: str, file_bytes: bytes) -> dict:
        files = {"file": (file_name, file_bytes, "text/csv")}
        response = requests.post(
            f"{self.base_url}/predict/csv",
            headers={"Authorization": self._headers().get("Authorization", "")},
            files=files,
            timeout=60
        )
        return self._handle_response(response)

    def deep_scan(self, target: str) -> dict:
        response = requests.post(
            f"{self.base_url}/recon/deep-scan",
            headers=self._headers(),
            json={"target": target},
            timeout=300  # deep scans take time — all modules run concurrently
        )
        return self._handle_response(response)

    def analyze_scan(self, scan_result: dict) -> dict:
        response = requests.post(
            f"{self.base_url}/recon/analyze-scan",
            headers=self._headers(),
            json={"scan_result": scan_result},
            timeout=60
        )
        return self._handle_response(response)

    def export_report(self, target: str, scan_result: dict, analysis: dict) -> bytes:
        response = requests.post(
            f"{self.base_url}/recon/export-report",
            headers=self._headers(),
            json={"target": target, "scan_result": scan_result, "analysis": analysis},
            timeout=30
        )
        if response.ok:
            return response.content
        raise APIClientError("Report export failed", status_code=response.status_code)
