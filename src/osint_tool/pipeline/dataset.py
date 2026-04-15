from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List


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
    dataset_path.parent.mkdir(parents=True, exist_ok=True)

    row = {key: features.get(key) for key in FIELDNAMES if key != "label"}
    row["label"] = label

    file_exists = dataset_path.exists()

    with dataset_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    return dataset_path