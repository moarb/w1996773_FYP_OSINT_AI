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
    if epoch is None:
        return None
    try:
        dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
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
    with raw_path.open("r", encoding="utf-8") as f:
        raw: Dict[str, Any] = json.load(f)

    data = raw.get("data", {}) or {}
    attributes = data.get("attributes", {}) or {}

    # VirusTotal fields we care about
    target = data.get("id")  # domain string
    stats = attributes.get("last_analysis_stats", {}) or {}
    reputation = attributes.get("reputation")
    last_analysis_epoch = attributes.get("last_analysis_date")

    now_iso = datetime.now(timezone.utc).isoformat()

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
        # placeholder for Phase 3 scoring (you fill later)
        "risk": {
            "score": None,
            "level": None,
            "reasons": [],
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = (target or "unknown").replace("/", "_")
    output_path = output_dir / f"{timestamp}__virustotal__domain__{safe_target}.json"

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(normalised, f, indent=2)

    return output_path