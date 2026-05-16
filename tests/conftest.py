from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def reload_env(tmp_path, monkeypatch):
    db_path = tmp_path / "test_api.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("ADMIN_USERNAME", "admin_user")
    monkeypatch.setenv("ADMIN_PASSWORD", "StrongPass123")
    monkeypatch.setenv(
        "MODEL_BUNDLE_PATH",
        str(Path(__file__).resolve().parents[1] / "models" / "trained_multiclass_smoke" / "best_model.pkl"),
    )
    import backend.core.config as config_module
    import backend.db.database as database_module
    import backend.db.models as models_module
    import backend.db.session as session_module
    import backend.services.auth_service as auth_service_module
    import backend.dependencies.auth as auth_dependency_module
    import backend.api.routes.auth as api_auth_module
    import backend.api.routes.alerts as api_alerts_module
    import backend.api.routes.monitoring as api_monitoring_module

    importlib.reload(config_module)
    importlib.reload(database_module)
    importlib.reload(models_module)
    importlib.reload(session_module)
    importlib.reload(auth_service_module)
    importlib.reload(auth_dependency_module)
    importlib.reload(api_auth_module)
    importlib.reload(api_alerts_module)
    importlib.reload(api_monitoring_module)
    yield


@pytest.fixture
def api_module():
    import backend.api.main as main_module
    import backend.db.database as db_module

    module = importlib.reload(main_module)
    db = importlib.reload(db_module)

    # Create all tables using the database module's engine (not from main)
    db.Base.metadata.create_all(bind=db.engine)
    return module


@pytest.fixture
def client(api_module):
    with TestClient(api_module.app) as c:
        yield c


@pytest.fixture
def auth_headers(client):
    login_resp = client.post(
        "/auth/login",
        json={"username": "admin_user", "password": "StrongPass123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def fake_prediction_result(row_count=1):
    from datetime import datetime
    return {
        "model_name": "test_model",
        "predictions": [
            {
                "predicted_label": "DDoS",
                "recommendations": ["Block IP", "Monitor traffic"]
            }
        ] * row_count,
        "summary": {
            "global_feature_importance": ["feature1", "feature2"]
        },
        "timestamp": datetime.now().isoformat()
    }
