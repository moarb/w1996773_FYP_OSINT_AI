"""
Normalised VirusTotal Domain Output Schema (v0.1)

Purpose:
- Turn raw VirusTotal JSON into a consistent structure that the rest of the pipeline can use
  (scoring + reporting), while keeping provenance back to the raw file.

Output shape:

{
  "meta": {
    "source": "virustotal",
    "query_type": "domain",
    "query": "<domain>",
    "collected_at": "<ISO timestamp>",
    "raw_file": "<relative path to raw JSON>",
    "tool_version": "0.1"
  },
  "results": {
    "reputation": <int or null>,
    "last_analysis_date": "<ISO timestamp or null>",
    "last_analysis_stats": {
      "malicious": <int>,
      "suspicious": <int>,
      "harmless": <int>,
      "undetected": <int>,
      "timeout": <int>
    }
  },
  "risk": {
    "score": null,
    "level": null,
    "reasons": []
  }
}
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional

TOOL_VERSION = "0.1"


def _epoch_to_iso(epoch: Optional[int]) -> Optional[str]:
    """Convert Unix epoch seconds to ISO-8601 string (UTC)."""

    # If no timestamp is present, return None
    if epoch is None:
        return None

    try:
        # Convert Unix timestamp into a readable UTC ISO format
        dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        # If conversion fails, return None instead of crashing
        return None


def normalise_virustotal_domain(raw_path: Path, output_dir: Path) -> Path:
    """
    Takes a raw VirusTotal domain JSON file and produces a normalised JSON file
    matching the schema defined in the module docstring.

    Args:
        raw_path: Path to raw VT JSON (saved from Phase 1).
        output_dir: Folder to write normalised JSON files to (e.g. data/normalised).

    Returns:
        Path to the new normalised JSON file.
    """

    # Load the raw VirusTotal JSON file
    with raw_path.open("r", encoding="utf-8") as f:
        raw: Dict[str, Any] = json.load(f)

    # Extract the nested sections we care about
    data = raw.get("data", {}) or {}
    attributes = data.get("attributes", {}) or {}

    # Pull out the key VirusTotal fields needed by the pipeline
    target = data.get("id")
    stats = attributes.get("last_analysis_stats", {}) or {}
    reputation = attributes.get("reputation")
    last_analysis_epoch = attributes.get("last_analysis_date")

    now_iso = datetime.now(timezone.utc).isoformat()

    # Build the normalised VirusTotal structure
    # This keeps the output consistent and easier to process later
    normalised: Dict[str, Any] = {
        "meta": {
            "source": "virustotal",
            "query_type": "domain",
            "query": target,
            "collected_at": now_iso,
            "raw_file": str(raw_path.as_posix()),
            "tool_version": TOOL_VERSION,
        },
        "results": {
            "reputation": reputation,
            "last_analysis_date": _epoch_to_iso(last_analysis_epoch),
            "last_analysis_stats": {
                "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "undetected": int(stats.get("undetected", 0) or 0),
                "timeout": int(stats.get("timeout", 0) or 0),
            },
        },
        # Risk fields are left empty at this stage
        # They will be populated later during scoring
        "risk": {
            "score": None,
            "level": None,
            "reasons": [],
        },
    }

    # Ensure the normalised output folder exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create a timestamped filename for the new normalised file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = (target or "unknown").replace("/", "_")
    output_path = output_dir / f"{timestamp}__virustotal__domain__{safe_target}.json"

    # Save the normalised VirusTotal output
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(normalised, f, indent=2)

    return output_path


def normalise_shodan_domain(raw_path: Path, output_dir: Path) -> Path:
    """
    Takes a raw Shodan domain JSON file and produces a normalised JSON file.
    """

    # Load the raw Shodan JSON file
    with raw_path.open("r", encoding="utf-8") as f:
        raw: Dict[str, Any] = json.load(f)

    # Extract the main fields from the raw Shodan structure
    query = raw.get("query")
    resolved_ip = raw.get("resolved_ip")
    host = raw.get("host", {}) or {}

    ports = host.get("ports", []) or []
    vulns = host.get("vulns", {}) or {}
    tags = host.get("tags", []) or []

    now_iso = datetime.now(timezone.utc).isoformat()

    # Build the normalised Shodan structure
    # This extracts infrastructure exposure indicators into a cleaner schema
    normalised: Dict[str, Any] = {
        "meta": {
            "source": "shodan",
            "query_type": "domain",
            "query": query,
            "collected_at": now_iso,
            "raw_file": str(raw_path.as_posix()),
            "tool_version": TOOL_VERSION,
        },
        "results": {
            "resolved_ip": resolved_ip,
            "open_ports": ports,
            "open_port_count": len(ports),
            "vulns_count": len(vulns),
            "vuln_ids": list(vulns.keys()) if isinstance(vulns, dict) else [],
            "org": host.get("org"),
            "isp": host.get("isp"),
            "country_code": host.get("country_code"),
            "os": host.get("os"),
            "tags": tags,
        },
        # Risk fields are left empty here and filled later during scoring
        "risk": {
            "score": None,
            "level": None,
            "reasons": [],
        },
    }

    # Ensure the normalised output folder exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create a timestamped filename for the new normalised file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = (query or "unknown").replace("/", "_")
    output_path = output_dir / f"{timestamp}__shodan__domain__{safe_target}.json"

    # Save the normalised Shodan output
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(normalised, f, indent=2)

    return output_path