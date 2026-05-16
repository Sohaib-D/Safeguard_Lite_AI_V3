import logging
import joblib
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("safeguard.ml.loader")

DEFAULT_MODEL_PATH = Path("models") / "trained_multiclass_smoke" / "best_model.pkl"

class ModelLoader:
    def __init__(self, model_path: str | None = None):
        candidate = model_path or os.getenv("MODEL_BUNDLE_PATH", "")
        self.model_path = Path(candidate) if candidate else DEFAULT_MODEL_PATH
        self._model = None

    def get_model(self) -> Any:
        if self._model is None:
            if not self.model_path.exists():
                logger.error(f"Model file not found at {self.model_path}")
                return None
            try:
                self._model = joblib.load(self.model_path)
                logger.info(f"Model loaded successfully from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        return self._model
