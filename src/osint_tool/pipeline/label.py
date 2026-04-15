from __future__ import annotations

from typing import Any, Dict


def assign_label_from_features(features: Dict[str, Any]) -> str:
    """
    Assign LOW / MEDIUM / HIGH using a transparent weak-supervision policy
    based on VirusTotal and Shodan indicators.
    """

    vt_malicious = int(features.get("vt_malicious", 0) or 0)
    vt_suspicious = int(features.get("vt_suspicious", 0) or 0)
    vt_reputation = int(features.get("vt_reputation", 0) or 0)
    shodan_vulns_count = int(features.get("shodan_vulns_count", 0) or 0)
    shodan_open_port_count = int(features.get("shodan_open_port_count", 0) or 0)
    shodan_has_risky_port = int(features.get("shodan_has_risky_port", 0) or 0)

    # HIGH risk indicators
    if vt_malicious > 0 or shodan_vulns_count > 0:
        return "HIGH"

    # MEDIUM risk indicators
    if (
        vt_suspicious > 0
        or vt_reputation < 0
        or shodan_open_port_count >= 5
        or shodan_has_risky_port == 1
    ):
        return "MEDIUM"

    # Otherwise LOW
    return "LOW"