from __future__ import annotations

import io
import pandas as pd
import pytest
from unittest.mock import patch


def test_end_to_end_upload_csv_prediction(client, auth_headers, monkeypatch):
    """CSV upload via /upload returns predictions in the correct shape."""
    monkeypatch.setattr(
        "backend.ml.predictor.ThreatPredictor.predict",
        lambda self, features: {"label": "Normal", "confidence": 0.95},
    )

    df = pd.DataFrame(
        [
            {
                "f0": 0.1, "f1": 0.2, "f2": 0.3,
                "f3": 0.4, "f4": 0.5, "f5": 0.6,
                "f6": 0.7, "f7": 0.8, "f8": 0.9,
                "f9": 1.0, "service": "http",
            },
        ]
    )
    file_bytes = df.to_csv(index=False).encode("utf-8")

    response = client.post(
        "/upload",
        headers=auth_headers,
        files={"file": ("events.csv", file_bytes, "text/csv")},
    )

    assert response.status_code == 200
    body = response.json()
    assert "predictions" in body
    assert "summary" in body
    assert isinstance(body["predictions"], list)
    assert len(body["predictions"]) == 1
    assert body["predictions"][0]["predicted_label"] == "Normal"


def test_end_to_end_json_predict(client, auth_headers, monkeypatch):
    """JSON predict via /predict returns predictions and a summary."""
    monkeypatch.setattr(
        "backend.ml.predictor.ThreatPredictor.predict",
        lambda self, features: {"label": "DDoS", "confidence": 0.88},
    )

    payload = {
        "records": [
            {"f0": 0.5, "f1": 0.6, "service": "dns"},
            {"f0": 0.1, "f1": 0.2, "service": "http"},
        ]
    }

    response = client.post("/predict", json=payload, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()

    assert "predictions" in body
    assert "summary" in body
    assert len(body["predictions"]) == 2
    assert body["predictions"][0]["predicted_label"] == "DDoS"
    assert body["summary"]["prediction_count"] == 2


def test_end_to_end_unauthenticated_request_is_rejected(client):
    """Requests without a Bearer token must be rejected with 401."""
    response = client.post("/predict", json={"records": []})
    assert response.status_code == 401


def test_end_to_end_stats_endpoint(client, auth_headers):
    """/stats endpoint returns the expected summary keys."""
    response = client.get("/stats", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert "total_alerts" in body
    assert "total_scans" in body
    assert "total_predictions" in body
