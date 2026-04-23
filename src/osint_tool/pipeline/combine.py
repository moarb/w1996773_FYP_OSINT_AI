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

    # Load the normalised VirusTotal file from disk
    with vt_path.open("r", encoding="utf-8") as f:
        vt_data: Dict[str, Any] = json.load(f)

    # Load the normalised Shodan file from disk
    with shodan_path.open("r", encoding="utf-8") as f:
        shodan_data: Dict[str, Any] = json.load(f)

    # Build one combined structure containing:
    # - metadata about the query
    # - file paths of the two normalised inputs
    # - source-specific results grouped together
    # - an empty risk block to be populated later
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

    # Make sure the output folder exists before writing the combined file
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create a unique timestamped filename for the combined file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("/", "_")
    output_path = output_dir / f"{timestamp}__combined__domain__{safe_domain}.json"

    # Save the combined multi-source analysis file to disk
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    # Return the file path so later stages can score and analyse it
    return output_path