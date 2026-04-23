from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier


# Define the exact feature columns used for training and prediction
# Keeping this fixed ensures consistency between the dataset and live predictions
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
    # Load the labelled training dataset from CSV
    df = pd.read_csv(csv_path)

    # Separate the input features (X) from the target labels (y)
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # Create a Random Forest classifier
    # n_estimators=50 means the model uses 50 decision trees
    # random_state=42 keeps results reproducible across runs
    model = RandomForestClassifier(n_estimators=50, random_state=42)

    # Train the model on the dataset
    model.fit(X, y)

    # Return the trained model so it can be used for prediction
    return model


def predict_risk(model, features: dict) -> str:
    # Keep only the features used during training
    filtered_features = {col: features[col] for col in FEATURE_COLUMNS}

    # Convert the single feature dictionary into a one-row DataFrame
    X = pd.DataFrame([filtered_features], columns=FEATURE_COLUMNS)

    # Predict the risk class (LOW / MEDIUM / HIGH)
    prediction = model.predict(X)[0]

    return prediction


def predict_risk_with_confidence(model, features: dict) -> tuple[str, float]:
    # Keep only the features the model expects
    filtered_features = {col: features[col] for col in FEATURE_COLUMNS}

    # Convert the features into the same tabular format used in training
    X = pd.DataFrame([filtered_features], columns=FEATURE_COLUMNS)

    # Predict the final class label
    prediction = model.predict(X)[0]

    # If the model supports probability output, calculate confidence
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]

        # Find the probability that matches the predicted class
        class_index = list(model.classes_).index(prediction)
        confidence = float(probabilities[class_index])
    else:
        confidence = 0.0

    # Return both the predicted class and the confidence score
    return prediction, confidence