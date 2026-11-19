"""Scikit-learn transformer for numeric URL features used by the lexical model."""
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from ml.features.extract_features import extract_features


class NumericURLFeatures(BaseEstimator, TransformerMixin):
    """Convert raw URLs into the project's deterministic numeric features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = [list(extract_features(url).values()) for url in X]
        return np.asarray(rows, dtype=np.float32)
