"""
predictor.py - loads the saved model ONCE and turns a URL string into a prediction.

Steps for every request: validate/normalize -> extract features (same code as training)
-> saved pipeline.predict_proba -> compare with the saved decision threshold.
The training dataset is never opened here, and the submitted URL is never visited.
"""
from __future__ import annotations

import json
import logging
import warnings
from pathlib import Path

import joblib
import pandas as pd
import sklearn

from feature_extractor import FEATURE_COLUMNS, features_frame, parse_url

MODEL_FILE = "phishguard_model.joblib"
META_FILE = "model_meta.json"
log = logging.getLogger("phishguard.predictor")

NOTES = [
    "This is a machine-learning estimate from the hostname text only, not a guarantee of safety.",
    "The path, query string and page content are ignored, and the site was not visited or checked against threat-intelligence lists.",
]


class ModelNotAvailableError(RuntimeError):
    """Model files are missing, unreadable or incompatible."""


class ModelService:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.pipeline = None
        self.meta: dict = {}

    @property
    def loaded(self) -> bool:
        return self.pipeline is not None

    def load(self) -> None:
        model_path, meta_path = self.model_dir / MODEL_FILE, self.model_dir / META_FILE
        if not model_path.is_file() or not meta_path.is_file():
            raise ModelNotAvailableError(
                "Model files not found. Train the model first by running: python train.py")
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            with warnings.catch_warnings():
                warnings.simplefilter("error", category=UserWarning)  # version-mismatch warnings become errors
                pipeline = joblib.load(model_path)
        except Exception as exc:  # corrupt file, incompatible scikit-learn, ...
            raise ModelNotAvailableError(
                f"Model could not be loaded ({type(exc).__name__}). Re-train it on this computer with: python train.py") from exc
        if meta.get("feature_columns") != FEATURE_COLUMNS:
            raise ModelNotAvailableError("Saved model features do not match feature_extractor.py. Re-train with: python train.py")
        classes = list(pipeline.named_steps["clf"].classes_)
        if 1 not in classes:
            raise ModelNotAvailableError("Saved model has an unexpected target encoding. Re-train with: python train.py")
        self.pipeline, self.meta, self._pos_idx = pipeline, meta, classes.index(1)
        log.info("Model loaded: %s v%s (scikit-learn %s)", meta.get("model_name"), meta.get("model_version"), sklearn.__version__)

    def predict(self, url) -> dict:
        if not self.loaded:
            raise ModelNotAvailableError("Model is not loaded. Train it first by running: python train.py")
        parsed = parse_url(url)                       # raises InvalidURLError
        row: pd.DataFrame = features_frame([parsed.host])
        p_phish = float(self.pipeline.predict_proba(row)[0][self._pos_idx])
        threshold = float(self.meta.get("decision_threshold", 0.5))
        is_phishing = p_phish >= threshold
        return {
            "prediction": "phishing" if is_phishing else "legitimate",
            "label": "Potential Phishing" if is_phishing else "Likely Legitimate",
            "phishing_probability": round(p_phish, 4),
            "legitimate_probability": round(1.0 - p_phish, 4),
            "decision_threshold": threshold,
            "analyzed_host": parsed.host,
            "scheme": parsed.scheme,
            "www_removed": parsed.www_removed,
            "path_or_query_ignored": parsed.has_path_or_query,
            "features": {k: (v if isinstance(v, str) else round(float(v), 4)) for k, v in row.iloc[0].items()},
            "model": {"name": self.meta.get("model_name"), "version": self.meta.get("model_version"),
                      "scope": self.meta.get("analysis_scope")},
            "notes": NOTES,
        }
