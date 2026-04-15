from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


TOOL_VERSION = "0.2"


def combine_normalised_sources(
    domain: str,
    vt_path: Path,
    shodan_path: Path,
    output_dir: Path,
) -> Path:
    """
    Combine one normalised VirusTotal file and one normalised Shodan file
    into a single multi-source analysis file.
    """

    with vt_path.open("r", encoding="utf-8") as f:
        vt_data: Dict[str, Any] = json.load(f)

    with shodan_path.open("r", encoding="utf-8") as f:
        shodan_data: Dict[str, Any] = json.load(f)

    combined: Dict[str, Any] = {
        "meta": {
            "query": domain,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "tool_version": TOOL_VERSION,
            "normalised_inputs": {
                "virustotal": str(vt_path.as_posix()),
                "shodan": str(shodan_path.as_posix()),
            },
        },
        "sources": {
            "virustotal": vt_data.get("results", {}),
            "shodan": shodan_data.get("results", {}),
        },
        "risk": {
            "score": None,
            "level": None,
            "reasons": [],
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("/", "_")
    output_path = output_dir / f"{timestamp}__combined__domain__{safe_domain}.json"

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    return output_path