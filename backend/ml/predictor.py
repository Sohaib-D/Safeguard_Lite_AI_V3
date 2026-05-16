import logging
import math
import pandas as pd
from typing import Dict, Any
from backend.ml.model_loader import ModelLoader

logger = logging.getLogger("safeguard.ml.predictor")

class ThreatPredictor:
    def __init__(self, loader: ModelLoader):
        self.loader = loader

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies a network event based on extracted features."""
        bundle = self.loader.get_model()
        if not bundle:
            return {"label": "MODEL_NOT_LOADED", "confidence": 0.0,
                    "error": "Model file could not be loaded. Check logs for path details."}

        try:
            # The model bundle is a dict: {model, preprocessor, feature_names, label_classes, ...}
            if isinstance(bundle, dict):
                model = bundle["model"]
                preprocessor = bundle.get("preprocessor")
                feature_names = bundle.get("feature_names", [])
                label_classes = bundle.get("label_classes", [])

                # Build a DataFrame with only the raw input columns (f0..f9 + service)
                # The preprocessor handles the encoding/scaling internally
                raw_num_cols = [f for f in features if f.startswith("f")]
                raw_cat_cols = [f for f in features if not f.startswith("f")]

                df = pd.DataFrame([features])

                if preprocessor is not None:
                    X = preprocessor.transform(df)
                else:
                    X = df.values

                probs = model.predict_proba(X)[0]
                pred_idx = probs.argmax()
                label = label_classes[pred_idx] if label_classes else str(model.classes_[pred_idx])
                confidence = float(probs[pred_idx])
                # Guard against NaN probabilities from model version mismatch
                if math.isnan(confidence):
                    confidence = 0.0

                return {
                    "label": str(label),
                    "confidence": confidence,
                    "all_probs": {
                        str(label_classes[i] if label_classes else model.classes_[i]): float(probs[i])
                        for i in range(len(probs))
                    }
                }
            else:
                # Legacy: bundle IS the sklearn model directly
                df = pd.DataFrame([features])
                label = bundle.predict(df)[0]
                probs = bundle.predict_proba(df)[0]
                confidence = float(max(probs))
                return {
                    "label": str(label),
                    "confidence": confidence,
                    "all_probs": {str(bundle.classes_[i]): float(probs[i]) for i in range(len(bundle.classes_))}
                }

        except Exception as e:
            expected = bundle.get("feature_names", []) if isinstance(bundle, dict) else "unknown"
            received = list(features.keys())
            logger.error(
                f"Prediction failed: {e} | "
                f"Expected features: {expected} | "
                f"Received features: {received}"
            )
            return {"label": "ERROR", "confidence": 0.0, "error": str(e)}
