from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict


def generate_markdown_report(scored_path: Path, output_dir: Path) -> Path:
    """
    Turns a scored normalised JSON file into a short analyst-friendly Markdown report.

    Args:
        scored_path: Path to the scored normalised JSON (contains meta/results/risk).
        output_dir: Folder to write reports to (e.g. data/reports).

    Returns:
        Path to the report file.
    """
    with scored_path.open("r", encoding="utf-8") as f:
        doc: Dict[str, Any] = json.load(f)

    meta = doc.get("meta", {}) or {}
    results = doc.get("results", {}) or {}
    risk = doc.get("risk", {}) or {}

    target = meta.get("query", "unknown")
    collected_at = meta.get("collected_at", "unknown")
    source = meta.get("source", "unknown")
    raw_file = meta.get("raw_file", "unknown")

    stats = results.get("last_analysis_stats", {}) or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    reputation = results.get("reputation", None)
    last_analysis_date = results.get("last_analysis_date", None)

    score = risk.get("score", None)
    level = risk.get("level", None)
    reasons = risk.get("reasons", []) or []

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = str(target).replace("/", "_")
    report_path = output_dir / f"{timestamp}__report__{safe_target}.md"

    lines = []
    lines.append(f"AI-Assisted OSINT Report")
    lines.append("")
    lines.append(f"Target: `{target}`")
    lines.append(f"Source: {source}")
    lines.append(f"Collected at: {collected_at}")
    lines.append(f"Raw file: `{raw_file}`")
    lines.append("")

    lines.append("Summary")
    lines.append(f"-Risk level: {level}**")
    lines.append(f"-Risk score: {score} / 100**")
    if last_analysis_date:
        lines.append(f"-Last analysis date (VT): {last_analysis_date}")
    if reputation is not None:
        lines.append(f"-Reputation (VT): {reputation}")
    lines.append("")

    lines.append("Detection Stats (latest)")
    lines.append(f"-Malicious: {malicious}")
    lines.append(f"-Suspicious: {suspicious}")
    lines.append(f"-Harmless: {harmless}")
    lines.append(f"-Undetected: {undetected}")
    lines.append(f"-Timeout: {timeout}")
    lines.append("")

    lines.append("Why this score?")
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("-No reasons provided.")
    lines.append("")

    lines.append("Notes / Next steps (prototype)")
    lines.append("-This prototype uses explainable rule-based scoring.")
    lines.append("-Next step: expand features (e.g., CVEs, categories, historical trends).")
    lines.append("-Future option: compare rules baseline vs ML/LLM approaches.")
    lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
