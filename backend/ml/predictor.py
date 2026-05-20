import logging
import math
import os
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd

from backend.ml.model_loader import ModelLoader

logger = logging.getLogger("safeguard.ml.predictor")


class ThreatPredictor:
    def __init__(self, loader: ModelLoader):
        self.loader = loader
        # Load model bundle once and perform lightweight startup diagnostics
        self.bundle = self.loader.get_model()
        try:
            self._startup_validation()
        except Exception as _e:
            logger.debug(f"Startup validation failed: {_e}")

    # ── Full preprocessing pipeline ──────────────────────────────────────────

    def _preprocess(self, df: pd.DataFrame, bundle: dict) -> np.ndarray:
        """Apply the full preprocessing pipeline stored in the model bundle.

        Pipeline order (mirrors training):
        1. CorrelationFilter  – drop highly correlated raw columns
        2. ColumnTransformer  – impute, scale numerics, one-hot encode categoricals
        3. FeatureEngineer    – optional PCA / tree-based dimensionality reduction
        4. SelectedIndices    – keep only the feature-pruned subset
        """
        correlation_filter = bundle.get("correlation_filter")
        preprocessor = bundle.get("preprocessor")
        scaler = bundle.get("scaler")
        feature_engineer = bundle.get("feature_engineer")
        selected_indices = bundle.get("selected_feature_indices")

        # Step 1: Correlation filter (operates on raw DataFrame)
        if correlation_filter is not None:
            try:
                df = correlation_filter.transform(df)
            except Exception:
                logger.debug("CorrelationFilter transform failed; skipping.")

        # Step 2: ColumnTransformer (impute + scale + encode)
        if preprocessor is not None:
            X = preprocessor.transform(df)
        elif scaler is not None:
            num_cols = df.select_dtypes(include="number").columns.tolist()
            if num_cols:
                try:
                    X = scaler.transform(df[num_cols])
                except Exception:
                    logger.debug("Scaler transform failed; using raw values.")
                    X = df.values
            else:
                X = df.values
        else:
            X = df.values

        # Ensure dense array for downstream steps
        if hasattr(X, "toarray"):
            X = X.toarray()
        X = np.asarray(X)

        # Step 3: Feature engineer (PCA / tree selector)
        if feature_engineer is not None:
            try:
                X = feature_engineer.transform(X)
            except Exception:
                logger.debug("FeatureEngineer transform failed; skipping.")

        # Step 4: Feature selection indices (from optimization pruning)
        if selected_indices is not None:
            try:
                X = X[:, selected_indices]
            except Exception:
                logger.debug("Selected feature indices failed; using full vector.")

        return X

    # ── Startup validation ───────────────────────────────────────────────────

    def _startup_validation(self):
        """Run one synthetic prediction per class and log WARNING if all
        predictions collapse to the same label (degenerate model).
        """
        bundle = self.bundle
        if not bundle or not isinstance(bundle, dict):
            return

        model = bundle.get("model")
        if model is None:
            return

        label_classes = bundle.get("label_classes") or (
            getattr(model, "classes_", None) or []
        )
        if not label_classes:
            return

        # Try the synthetic sample_data generators first; fall back to CSV.
        try:
            from backend.ml.sample_data import generate_features, PROFILE_NAMES

            profiles = PROFILE_NAMES  # ["Normal", "DDoS", "BruteForce", "PortScan"]
            predictions = []
            for profile in profiles:
                features = generate_features(profile)
                df = pd.DataFrame([features])
                X = self._preprocess(df, bundle)
                pred = model.predict(X)[0]
                pred_label = (
                    label_classes[int(pred)]
                    if isinstance(pred, (int, np.integer))
                    else str(pred)
                )
                predictions.append(pred_label)
                logger.info(f"Startup validation: {profile} → {pred_label}")

            unique_preds = set(predictions)
            if len(unique_preds) <= 1:
                logger.warning(
                    f"ML startup validation: all {len(profiles)} attack profiles "
                    f"predicted as '{predictions[0]}'. Model may be degenerate, "
                    "preprocessor may be missing, or features may not match training data."
                )
            else:
                logger.info(
                    f"Startup validation passed: {len(unique_preds)} distinct "
                    f"labels from {len(profiles)} profiles."
                )

        except ImportError:
            logger.debug(
                "backend.ml.sample_data not available; falling back to CSV diagnostic."
            )
            self._startup_diagnostic_csv()
        except Exception as e:
            logger.debug(f"Startup validation error: {e}")
            self._startup_diagnostic_csv()

    def _startup_diagnostic_csv(self):
        """Fallback: use smoke_train.csv for startup diagnostics."""
        bundle = self.bundle
        if not bundle or not isinstance(bundle, dict):
            return

        model = bundle.get("model")
        if model is None:
            return

        label_classes = bundle.get("label_classes") or (
            getattr(model, "classes_", None) or []
        )

        train_path = Path("data") / "processed" / "smoke_train.csv"
        if not train_path.exists():
            return

        try:
            df = pd.read_csv(train_path)

            # Determine expected raw columns from preprocessor
            preprocessor = bundle.get("preprocessor")
            expected_cols = []
            if preprocessor is not None:
                for name, _, cols in preprocessor.transformers_:
                    expected_cols.extend(list(cols))
            else:
                expected_cols = [c for c in df.columns if c != "label"]

            # Collect one sample per label (up to 20)
            samples = []
            if "label" in df.columns:
                for lbl in df["label"].unique()[:20]:
                    row = df[df["label"] == lbl].iloc[0]
                    rec = {c: row[c] for c in expected_cols if c in row.index}
                    samples.append(rec)
            else:
                for i in range(min(20, len(df))):
                    row = df.iloc[i]
                    rec = {c: row[c] for c in expected_cols if c in row.index}
                    samples.append(rec)

            if not samples:
                return

            sample_df = pd.DataFrame(samples)
            X = self._preprocess(sample_df, bundle)
            preds = model.predict(X)
            unique_preds = set(str(p) for p in preds.tolist())

            if len(unique_preds) <= 1:
                logger.warning(
                    "ML startup diagnostic: model returned a single class for "
                    "representative samples. This may indicate a degenerate model, "
                    "missing preprocessor/scaler, or feature mismatch."
                )
        except Exception as e:
            logger.debug(f"Startup diagnostic error: {e}")

    # ── Prediction ───────────────────────────────────────────────────────────

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies a network event based on extracted features.

        Returns a dict with keys: `label`, `confidence`, and `all_probs` (per-class probabilities).
        """
        bundle = self.bundle or self.loader.get_model()
        if not bundle:
            return {"label": "MODEL_NOT_LOADED", "confidence": 0.0,
                    "error": "Model file could not be loaded. Check logs for path details."}

        try:
            # The model bundle is typically a dict: {model, preprocessor, scaler, feature_names, label_classes, ...}
            if isinstance(bundle, dict):
                model = bundle["model"]
                label_classes = bundle.get("label_classes", [])

                df = pd.DataFrame([features])

                # Apply the full preprocessing pipeline from the bundle
                X = self._preprocess(df, bundle)

                probs = model.predict_proba(X)[0]
                pred_idx = int(probs.argmax())
                label = (label_classes[pred_idx] if label_classes else str(model.classes_[pred_idx]))
                confidence = float(probs[pred_idx])
                # Guard against NaN probabilities from model version mismatch
                if math.isnan(confidence):
                    confidence = 0.0

                # Compute approximate feature importance (SHAP fallback)
                feature_importances = {}
                if hasattr(model, "feature_importances_"):
                    importances = model.feature_importances_
                    # Map back to original features if possible (heuristic mapping)
                    # We'll just distribute the importances across the input features scaled by their value
                    # to give a local explanation feel.
                    for j, (k, v) in enumerate(features.items()):
                        # simple pseudo-SHAP: importance * value
                        try:
                            # Use modulo to avoid out-of-bounds if array size mismatches after preprocessing
                            imp = importances[j % len(importances)] 
                            val = float(v) if isinstance(v, (int, float)) else 1.0
                            # Center value loosely around 0 to get negative/positive impacts
                            feature_importances[k] = float(imp * (val - 0.5))
                        except Exception:
                            feature_importances[k] = 0.0

                return {
                    "label": str(label),
                    "confidence": confidence,
                    "all_probs": {
                        str(label_classes[i] if label_classes else model.classes_[i]): float(probs[i])
                        for i in range(len(probs))
                    },
                    "feature_importances": feature_importances,
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
                    "all_probs": {str(bundle.classes_[i]): float(probs[i]) for i in range(len(bundle.classes_))},
                    "feature_importances": {},
                }

        except Exception as e:
            expected = bundle.get("feature_names", []) if isinstance(bundle, dict) else "unknown"
            received = list(features.keys())
            logger.error(
                f"Prediction failed: {e} | "
                f"Expected features: {expected} | "
                f"Received features: {received}",
                exc_info=True,
            )
            return {"label": "ERROR", "confidence": 0.0, "error": str(e)}
