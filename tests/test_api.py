from __future__ import annotations

import pytest


def test_protected_endpoints_require_auth(client):
    response = client.get("/model_info")
    assert response.status_code == 401

    response = client.post("/predict", json={"records": []})
    assert response.status_code == 401


def test_auth_flow_create_admin_and_login(client):
    create_resp = client.post(
        "/auth/create-admin",
        json={"username": "new_admin", "password": "StrongPass123"},
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["username"] == "new_admin"

    login_resp = client.post(
        "/auth/login",
        json={"username": "new_admin", "password": "StrongPass123"},
    )
    assert login_resp.status_code == 200
    body = login_resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_predict_json_endpoint_returns_expected_shape(client, auth_headers, monkeypatch):
    def fake_predict(record):
        return {"label": "Normal", "confidence": 0.95}

    monkeypatch.setattr(
        "backend.ml.predictor.ThreatPredictor.predict",
        lambda self, features: {"label": "Normal", "confidence": 0.95},
    )

    payload = {
        "records": [
            {"f0": 0.1, "f1": 0.2, "service": "http"},
            {"f0": 0.5, "f1": 0.6, "service": "dns"},
        ]
    }

    response = client.post("/predict", json=payload, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()

    assert "predictions" in body
    assert len(body["predictions"]) == 2
    assert body["predictions"][0]["predicted_label"] == "Normal"
    assert body["predictions"][0]["confidence"] == 0.95


def test_predict_csv_endpoint_returns_expected_shape(client, auth_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "backend.ml.predictor.ThreatPredictor.predict",
        lambda self, features: {"label": "Normal", "confidence": 0.95},
    )

    file_path = tmp_path / "sample.csv"
    file_path.write_text("f0,f1,service\n0.1,0.2,http\n")

    with open(file_path, "rb") as f:
        response = client.post(
            "/upload",
            headers=auth_headers,
            files={"file": ("sample.csv", f, "text/csv")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["prediction_count"] == 1
    assert body["predictions"][0]["predicted_label"] == "Normal"
