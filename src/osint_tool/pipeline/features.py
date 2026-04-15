from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


RISKY_PORTS = {21, 23, 445, 3389}


def extract_features_from_combined(combined_path: Path) -> Dict[str, Any]:
    """
    Extract a flat feature dictionary from a combined VT + Shodan file.
    This is used for ML training and evaluation.
    """
    data = json.loads(combined_path.read_text(encoding="utf-8"))

    vt = (data.get("sources", {}) or {}).get("virustotal", {}) or {}
    shodan = (data.get("sources", {}) or {}).get("shodan", {}) or {}

    vt_stats = vt.get("last_analysis_stats", {}) or {}
    shodan_ports = shodan.get("open_ports", []) or []
    shodan_tags = shodan.get("tags", []) or []

    features: Dict[str, Any] = {
        "query": data.get("meta", {}).get("query"),
        "vt_reputation": int(vt.get("reputation", 0) or 0),
        "vt_malicious": int(vt_stats.get("malicious", 0) or 0),
        "vt_suspicious": int(vt_stats.get("suspicious", 0) or 0),
        "vt_harmless": int(vt_stats.get("harmless", 0) or 0),
        "vt_undetected": int(vt_stats.get("undetected", 0) or 0),
        "shodan_open_port_count": int(shodan.get("open_port_count", 0) or 0),
        "shodan_vulns_count": int(shodan.get("vulns_count", 0) or 0),
        "shodan_has_risky_port": int(any(port in RISKY_PORTS for port in shodan_ports)),
        "shodan_is_cdn": int("cdn" in [str(tag).lower() for tag in shodan_tags]),
    }

    return features