from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier


FEATURE_COLUMNS = [
    "vt_reputation",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "shodan_open_port_count",
    "shodan_vulns_count",
    "shodan_has_risky_port",
    "shodan_is_cdn",
]


def train_model(csv_path: str = "data/ml/training_data.csv"):
    df = pd.read_csv(csv_path)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)

    return model


def predict_risk(model, features: dict) -> str:
    filtered_features = {col: features[col] for col in FEATURE_COLUMNS}
    X = pd.DataFrame([filtered_features], columns=FEATURE_COLUMNS)
    prediction = model.predict(X)[0]
    return prediction


def predict_risk_with_confidence(model, features: dict) -> tuple[str, float]:
    filtered_features = {col: features[col] for col in FEATURE_COLUMNS}
    X = pd.DataFrame([filtered_features], columns=FEATURE_COLUMNS)

    prediction = model.predict(X)[0]

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        class_index = list(model.classes_).index(prediction)
        confidence = float(probabilities[class_index])
    else:
        confidence = 0.0

    return prediction, confidence