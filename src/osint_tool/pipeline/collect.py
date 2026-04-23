import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from osint_tool.config import settings
from osint_tool.clients.virustotal_client import VirusTotalClient
from osint_tool.clients.shodan_client import ShodanClient


def _ensure_dir(path: Path) -> None:
    # Make sure the target folder exists before writing files into it
    path.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    # Create a UTC timestamp used in filenames so each run is unique
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def save_raw_json(payload: Dict[str, Any], source: str, query_type: str, query: str) -> Path:
    # Define the folder where raw collected API responses will be stored
    raw_dir = Path(settings.data_dir) / "raw"
    _ensure_dir(raw_dir)

    # Make the query safe to use inside a filename
    safe_query = query.replace(":", "_").replace("/", "_")

    # Build a timestamped filename so files do not overwrite each other
    filename = f"{_timestamp()}__{source}__{query_type}__{safe_query}.json"
    out_path = raw_dir / filename

    # Write the raw JSON payload to disk
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Return the file path so later stages can use it
    return out_path


def collect_from_virustotal(query_type: str, query: str) -> Path:
    # Create a VirusTotal client using the API key from config
    client = VirusTotalClient(settings.virustotal_api_key)

    # Standardise the query type so checks are case-insensitive
    qt = query_type.lower().strip()

    # Call the correct VirusTotal endpoint depending on the type of input
    if qt == "domain":
        data = client.get_domain_report(query)
    elif qt == "ip":
        data = client.get_ip_report(query)
    elif qt in {"hash", "filehash", "file_hash"}:
        data = client.get_file_hash_report(query)
    else:
        raise ValueError("query_type must be one of: domain, ip, hash")

    # Save the raw VirusTotal response and return the file path
    return save_raw_json(data, source="virustotal", query_type=qt, query=query)


def collect_from_shodan(query_type: str, query: str) -> Path:
    # Create a Shodan client using the API key from config
    client = ShodanClient(settings.shodan_api_key)

    # Standardise the query type so checks are case-insensitive
    qt = query_type.lower().strip()

    # For a domain query, resolve the domain and fetch Shodan host data
    if qt == "domain":
        data = client.get_domain_bundle(query)

    # For an IP query, use the IP directly as both the query and resolved IP
    elif qt == "ip":
        data = {
            "query": query,
            "resolved_ip": query,
            "host": client.get_host(query),
        }
    else:
        raise ValueError("Shodan query_type must be one of: domain, ip")

    # Save the raw Shodan response and return the file path
    return save_raw_json(data, source="shodan", query_type=qt, query=query)