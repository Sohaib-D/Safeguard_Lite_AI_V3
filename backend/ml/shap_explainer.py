import logging
import shap
import pandas as pd
from typing import Dict, Any
from backend.ml.model_loader import ModelLoader

logger = logging.getLogger("safeguard.ml.shap")

class ExplainableAI:
    def __init__(self, loader: ModelLoader):
        self.loader = loader
        self._explainer = None

    def _init_explainer(self):
        model = self.loader.get_model()
        if model and self._explainer is None:
            # SHAP TreeExplainer is best for RandomForest/XGBoost
            self._explainer = shap.TreeExplainer(model)

    def explain_prediction(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Explains why a certain prediction was made."""
        self._init_explainer()
        if not self._explainer:
            return {}

        try:
            df = pd.DataFrame([features])
            shap_values = self._explainer.shap_values(df)
            
            # For multiclass, shap_values is a list of arrays
            # We take the values for the predicted class
            # Simplified for summary:
            import numpy as np
            feature_names = df.columns.tolist()
            # Mean absolute SHAP values per feature
            importances = np.abs(shap_values).mean(axis=0).flatten()
            
            return dict(zip(feature_names, importances.tolist()))
        except Exception as e:
            logger.error(f"SHAP explanation failed: {e}")
            return {}
