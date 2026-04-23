from __future__ import annotations

# Used to generate a UTC timestamp for when the final result is produced
from datetime import datetime, timezone

# Used to handle file paths safely when reading/writing pipeline outputs
from pathlib import Path

# Import each pipeline stage
# These are the building blocks of the full end-to-end analysis process
from osint_tool.pipeline.collect import collect_from_virustotal, collect_from_shodan
from osint_tool.pipeline.normalise import normalise_virustotal_domain, normalise_shodan_domain
from osint_tool.pipeline.combine import combine_normalised_sources
from osint_tool.pipeline.score import score_combined_domain
from osint_tool.pipeline.features import extract_features_from_combined
from osint_tool.pipeline.label import assign_label_from_features
from osint_tool.pipeline.ml_model import train_model, predict_risk_with_confidence
from osint_tool.pipeline.report import generate_combined_markdown_report


def _build_summary_text(domain: str, rule_level: str, rule_score: int, reasons: list[str]) -> str:
    """
    Build a short natural-language summary of the final rule-based result.

    This is mainly used for:
    - the Streamlit interface
    - the generated report

    It converts structured results into a readable sentence for the user.
    """
    if reasons:
        # Join the reasons into one readable string separated by semicolons
        joined = "; ".join(reasons)
    else:
        # Fallback in case no reasons were generated
        joined = "no significant malicious, suspicious, or exposure indicators were detected"

    # Return a human-readable summary sentence
    return (
        f"The domain {domain} was classified as {rule_level} risk with a rule-based score "
        f"of {rule_score}/100. This decision was based on the following evidence: {joined}."
    )


def analyse_domain(domain: str) -> dict:
    """
    Run the full domain analysis pipeline from start to finish.

    High-level flow:
    1. Collect raw data from VirusTotal and Shodan
    2. Normalise each source into a consistent structure
    3. Combine both normalised outputs into one file
    4. Apply rule-based scoring
    5. Extract structured features
    6. Assign a weak-supervision label from features
    7. Train/load the ML model and generate prediction + confidence
    8. Build a final result object
    9. Generate a markdown report
    10. Return the final result dictionary
    """

    # 1. COLLECT RAW DATA
    # Query VirusTotal and save its raw output to disk
    vt_raw = collect_from_virustotal("domain", domain)

    # Query Shodan and save its raw output to disk
    shodan_raw = collect_from_shodan("domain", domain)

    # 2. NORMALISE RAW OUTPUTS
    # Convert raw VirusTotal JSON into a consistent internal schema
    vt_norm = normalise_virustotal_domain(Path(vt_raw), Path("data/normalised"))

    # Convert raw Shodan JSON into a consistent internal schema
    shodan_norm = normalise_shodan_domain(Path(shodan_raw), Path("data/normalised"))

    # 3. COMBINE SOURCES
    # Merge the two normalised files into one multi-source representation
    combined = combine_normalised_sources(
        domain=domain,
        vt_path=Path(vt_norm),
        shodan_path=Path(shodan_norm),
        output_dir=Path("data/normalised"),
    )

    # 4. RULE-BASED SCORING
    # Apply the rule-based scoring system to the combined file
    # This returns:
    # - scored_path: path to updated scored JSON
    # - scored_json: the actual scored data loaded as a dictionary
    scored_path, scored_json = score_combined_domain(Path(combined))

    # 5. FEATURE EXTRACTION
    # Convert the combined scored file into a flat feature dictionary
    # This is used for ML prediction and weak-supervision labelling
    features = extract_features_from_combined(Path(scored_path))

    # 6. RULE LABEL FROM FEATURES
    # Generate a transparent label (LOW / MEDIUM / HIGH)
    # from the extracted features
    # This acts as a weak-supervision label
    rule_label = assign_label_from_features(features)

    # 7. ML PREDICTION
    # Train/load the Random Forest model from the dataset
    model = train_model()

    # Predict ML class and probability-like confidence score
    ml_prediction, ml_confidence = predict_risk_with_confidence(model, features)

    # 8. BUILD SOURCE SUMMARY
    # Extract relevant VirusTotal data from the scored combined JSON
    vt = scored_json["sources"]["virustotal"]
    vt_stats = vt["last_analysis_stats"]

    # Extract relevant Shodan data from the scored combined JSON
    shodan = scored_json["sources"]["shodan"]

    # Create a simplified source summary for use in:
    # - Streamlit UI
    # - final report
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

    # 9. BUILD FINAL RESULT OBJECT
    # This is the main dictionary returned by this function.
    # It contains all the important outputs needed by:
    # - the CLI
    # - Streamlit
    # - report generation
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

    # 10. GENERATE REPORT
    # Create a markdown report from the final result object
    report_path = generate_combined_markdown_report(result, Path("data/reports"))

    # Store the report path inside the result dictionary
    result["report_path"] = str(report_path)

    # 11. RETURN FINAL OUTPUT
    # Return one complete dictionary containing all outputs
    return result