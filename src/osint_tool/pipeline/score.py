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


def score_shodan_domain(normalised_path: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Reads a normalised Shodan domain JSON and writes back the same file
    with the 'risk' block populated.
    """
    data: Dict[str, Any] = json.loads(normalised_path.read_text(encoding="utf-8"))

    results = data.get("results", {}) or {}
    open_port_count = int(results.get("open_port_count", 0) or 0)
    vulns_count = int(results.get("vulns_count", 0) or 0)
    open_ports = results.get("open_ports", []) or []

    score = 0
    reasons = []

    # Justified baseline rules:
    # vulnerabilities indicate stronger risk than exposure alone
    if vulns_count > 0:
        score += 50
        reasons.append(f"{vulns_count} vulnerability indicators found in Shodan")

    if open_port_count >= 5:
        score += 20
        reasons.append(f"{open_port_count} open ports detected")

    risky_ports = {21, 23, 3389, 445}
    exposed_risky_ports = sorted(risky_ports.intersection(set(open_ports)))
    if exposed_risky_ports:
        score += 20
        reasons.append(f"potentially risky exposed ports: {', '.join(map(str, exposed_risky_ports))}")

    if not reasons:
        reasons.append("no significant exposure indicators detected in Shodan")

    score = min(score, 100)

    risk = data.get("risk", {}) or {}
    risk["score"] = score
    risk["level"] = _risk_level(score)
    risk["reasons"] = reasons

    data["risk"] = risk

    normalised_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return normalised_path, data


def score_combined_domain(combined_path: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Score a combined VirusTotal + Shodan normalised file.
    """

    data: Dict[str, Any] = json.loads(combined_path.read_text(encoding="utf-8"))

    vt = (data.get("sources", {}) or {}).get("virustotal", {}) or {}
    shodan = (data.get("sources", {}) or {}).get("shodan", {}) or {}

    vt_stats = vt.get("last_analysis_stats", {}) or {}
    vt_malicious = int(vt_stats.get("malicious", 0) or 0)
    vt_suspicious = int(vt_stats.get("suspicious", 0) or 0)
    vt_reputation = vt.get("reputation", None)

    shodan_open_port_count = int(shodan.get("open_port_count", 0) or 0)
    shodan_vulns_count = int(shodan.get("vulns_count", 0) or 0)
    shodan_open_ports = shodan.get("open_ports", []) or []

    score = 0
    reasons = []

    # VirusTotal signals (strongest)
    if vt_malicious > 0:
        score += 70
        reasons.append(f"{vt_malicious} VirusTotal engines flagged the domain as malicious")

    if vt_suspicious > 0:
        score += 20
        reasons.append(f"{vt_suspicious} VirusTotal engines flagged the domain as suspicious")

    if isinstance(vt_reputation, int) and vt_reputation < 0:
        score += 10
        reasons.append(f"VirusTotal reputation is negative ({vt_reputation})")

    # Shodan signals (supporting infrastructure risk)
    if shodan_vulns_count > 0:
        score += 20
        reasons.append(f"Shodan found {shodan_vulns_count} vulnerability indicators")

    if shodan_open_port_count >= 5:
        score += 10
        reasons.append(f"Shodan detected {shodan_open_port_count} open ports")

    risky_ports = {21, 23, 445, 3389}
    exposed_risky_ports = sorted(risky_ports.intersection(set(shodan_open_ports)))
    if exposed_risky_ports:
        score += 10
        reasons.append(
            f"Shodan detected potentially risky exposed ports: {', '.join(map(str, exposed_risky_ports))}"
        )

    if not reasons:
        reasons.append("no significant malicious, suspicious, or exposure indicators detected")

    score = min(score, 100)

    risk = data.get("risk", {}) or {}
    risk["score"] = score
    risk["level"] = _risk_level(score)
    risk["reasons"] = reasons

    data["risk"] = risk

    combined_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return combined_path, data