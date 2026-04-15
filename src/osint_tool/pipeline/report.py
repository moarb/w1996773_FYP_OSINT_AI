from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def generate_combined_markdown_report(result: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    domain = result["domain"].replace("/", "_")
    report_path = output_dir / f"{timestamp}__combined_report__{domain}.md"

    vt = result["source_summary"]["virustotal"]
    shodan = result["source_summary"]["shodan"]

    reasons_md = "\n".join([f"- {reason}" for reason in result["reasons"]]) or "- No reasons recorded"

    report_text = f"""
AI-Assisted OSINT Report

Domain: {result["domain"]}
Generated at: {result["generated_at"]}


FINAL ASSESSMENT

Rule-based score: {result["rule_score"]} / 100  
Risk level: {result["rule_level"]}  
ML prediction: {result["ml_prediction"]}  
ML confidence: {result["ml_confidence"]:.2f}  
Agreement between systems: {"Yes" if result["rule_level"] == result["ml_prediction"] else "No"}


WHY THIS RESULT

{reasons_md}


SOURCE SUMMARY

[VirusTotal]
Reputation: {vt["reputation"]}
Malicious: {vt["malicious"]}
Suspicious: {vt["suspicious"]}
Harmless: {vt["harmless"]}
Undetected: {vt["undetected"]}

[Shodan]
Resolved IP: {shodan["resolved_ip"]}
Open port count: {shodan["open_port_count"]}
Open ports: {shodan["open_ports"]}
Vulnerabilities: {shodan["vulns_count"]}
Risky port exposed: {shodan["has_risky_port"]}
CDN detected: {shodan["is_cdn"]}


SUMMARY

{result["summary_text"]}


NOTES

- Rule-based scoring provides transparent, explainable reasoning
- ML prediction is trained on OSINT-derived features for classification
"""

    report_path.write_text(report_text, encoding="utf-8")
    return report_path

