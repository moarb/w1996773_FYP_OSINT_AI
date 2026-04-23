from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


# Define the structure of the dataset (column names)
FIELDNAMES: List[str] = [
    "query",
    "vt_reputation",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "shodan_open_port_count",
    "shodan_vulns_count",
    "shodan_has_risky_port",
    "shodan_is_cdn",
    "label",
]


def append_features_to_dataset(
    features: Dict[str, Any],
    label: str,
    dataset_path: Path,
) -> Path:
    """
    Append one feature row to a CSV dataset.
    Creates the CSV with headers if it does not already exist.
    """

    # Ensure the dataset folder exists before writing
    dataset_path.parent.mkdir(parents=True, exist_ok=True)

    # Build a row using only the required feature fields
    row = {key: features.get(key) for key in FIELDNAMES if key != "label"}

    # Add the label (LOW / MEDIUM / HIGH)
    row["label"] = label

    # Check if the file already exists (to decide whether to write headers)
    file_exists = dataset_path.exists()

    # Open the CSV file in append mode
    with dataset_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

        # If file is new, write the header row first
        if not file_exists:
            writer.writeheader()

        # Append the new feature row
        writer.writerow(row)

    # Return the dataset path for reference
    return dataset_path