from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple


def _risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_normalised_domain(normalised_path: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Reads a normalised VirusTotal domain JSON (v0.1) and writes back the same file
    with the 'risk' block populated (score, level, reasons).

    Returns: (updated_file_path, updated_json_dict)
    """
    data: Dict[str, Any] = json.loads(normalised_path.read_text(encoding="utf-8"))

    stats = (data.get("results", {}) or {}).get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    reputation = data.get("results", {}).get("reputation", None)

    score = 0
    reasons = []

    # Baseline explainable rules (simple, defendable, easy to demo)
    if malicious > 0:
        score += 70
        reasons.append(f"{malicious} sources flagged as malicious")

    if suspicious > 0:
        score += 30
        reasons.append(f"{suspicious} sources flagged as suspicious")

    # reputation can be None; if present and negative, bump risk a bit
    if isinstance(reputation, int) and reputation < 0:
        score += 10
        reasons.append(f"negative reputation ({reputation})")

    # If nothing triggered, explain why it's low
    if not reasons:
        reasons.append("no malicious or suspicious detections in the latest analysis")

    # Cap score
    score = min(score, 100)

    risk = data.get("risk", {}) or {}
    risk["score"] = score
    risk["level"] = _risk_level(score)
    risk["reasons"] = reasons

    data["risk"] = risk

    normalised_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return normalised_path, data
