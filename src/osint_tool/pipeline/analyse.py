from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from osint_tool.pipeline.collect import collect_from_virustotal, collect_from_shodan
from osint_tool.pipeline.normalise import normalise_virustotal_domain, normalise_shodan_domain
from osint_tool.pipeline.combine import combine_normalised_sources
from osint_tool.pipeline.score import score_combined_domain
from osint_tool.pipeline.features import extract_features_from_combined
from osint_tool.pipeline.label import assign_label_from_features
from osint_tool.pipeline.ml_model import train_model, predict_risk_with_confidence
from osint_tool.pipeline.report import generate_combined_markdown_report


def _build_summary_text(domain: str, rule_level: str, rule_score: int, reasons: list[str]) -> str:
    if reasons:
        joined = "; ".join(reasons)
    else:
        joined = "no significant malicious, suspicious, or exposure indicators were detected"

    return (
        f"The domain {domain} was classified as {rule_level} risk with a rule-based score "
        f"of {rule_score}/100. This decision was based on the following evidence: {joined}."
    )


def analyse_domain(domain: str) -> dict:
    # 1. collect
    vt_raw = collect_from_virustotal("domain", domain)
    shodan_raw = collect_from_shodan("domain", domain)

    # 2. normalise
    vt_norm = normalise_virustotal_domain(Path(vt_raw), Path("data/normalised"))
    shodan_norm = normalise_shodan_domain(Path(shodan_raw), Path("data/normalised"))

    # 3. combine
    combined = combine_normalised_sources(
        domain=domain,
        vt_path=Path(vt_norm),
        shodan_path=Path(shodan_norm),
        output_dir=Path("data/normalised"),
    )

    # 4. rule-based score
    scored_path, scored_json = score_combined_domain(Path(combined))

    # 5. extract features
    features = extract_features_from_combined(Path(scored_path))

    # 6. label from features (rule label)
    rule_label = assign_label_from_features(features)

    # 7. ML prediction
    model = train_model()
    ml_prediction, ml_confidence = predict_risk_with_confidence(model, features)

    vt = scored_json["sources"]["virustotal"]
    vt_stats = vt["last_analysis_stats"]
    shodan = scored_json["sources"]["shodan"]

    source_summary = {
        "virustotal": {
            "reputation": vt.get("reputation"),
            "malicious": vt_stats.get("malicious", 0),
            "suspicious": vt_stats.get("suspicious", 0),
            "harmless": vt_stats.get("harmless", 0),
            "undetected": vt_stats.get("undetected", 0),
        },
        "shodan": {
            "resolved_ip": shodan.get("resolved_ip"),
            "open_port_count": shodan.get("open_port_count", 0),
            "open_ports": shodan.get("open_ports", []),
            "vulns_count": shodan.get("vulns_count", 0),
            "has_risky_port": features.get("shodan_has_risky_port", 0),
            "is_cdn": features.get("shodan_is_cdn", 0),
        },
    }

    result = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_score": scored_json["risk"]["score"],
        "rule_level": scored_json["risk"]["level"],
        "rule_label": rule_label,
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "reasons": scored_json["risk"]["reasons"],
        "source_summary": source_summary,
        "features": features,
        "summary_text": _build_summary_text(
            domain=domain,
            rule_level=scored_json["risk"]["level"],
            rule_score=scored_json["risk"]["score"],
            reasons=scored_json["risk"]["reasons"],
        ),
    }

    report_path = generate_combined_markdown_report(result, Path("data/reports"))
    result["report_path"] = str(report_path)

    return result