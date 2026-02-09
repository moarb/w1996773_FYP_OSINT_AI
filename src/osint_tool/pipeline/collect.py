import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from osint_tool.config import settings
from osint_tool.clients.virustotal_client import VirusTotalClient


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def save_raw_json(payload: Dict[str, Any], source: str, query_type: str, query: str) -> Path:
    raw_dir = Path(settings.data_dir) / "raw"
    _ensure_dir(raw_dir)

    safe_query = query.replace(":", "_").replace("/", "_")
    filename = f"{_timestamp()}__{source}__{query_type}__{safe_query}.json"
    out_path = raw_dir / filename

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return out_path


def collect_from_virustotal(query_type: str, query: str) -> Path:
    client = VirusTotalClient(settings.virustotal_api_key)

    qt = query_type.lower().strip()
    if qt == "domain":
        data = client.get_domain_report(query)
    elif qt == "ip":
        data = client.get_ip_report(query)
    elif qt in {"hash", "filehash", "file_hash"}:
        data = client.get_file_hash_report(query)
    else:
        raise ValueError("query_type must be one of: domain, ip, hash")

    return save_raw_json(data, source="virustotal", query_type=qt, query=query)
