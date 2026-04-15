from pathlib import Path
import sys

from osint_tool.pipeline.collect import collect_from_virustotal, collect_from_shodan
from osint_tool.pipeline.normalise import normalise_virustotal_domain, normalise_shodan_domain
from osint_tool.pipeline.combine import combine_normalised_sources
from osint_tool.pipeline.score import score_combined_domain
from osint_tool.pipeline.features import extract_features_from_combined
from osint_tool.pipeline.label import assign_label_from_features
from osint_tool.pipeline.dataset import append_features_to_dataset


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python build_dataset_row.py <domain>")
        sys.exit(1)

    query = sys.argv[1].strip()

    # 1. collect raw data
    vt_raw = collect_from_virustotal("domain", query)
    shodan_raw = collect_from_shodan("domain", query)

    # 2. normalise both sources
    vt_norm = normalise_virustotal_domain(Path(vt_raw), Path("data/normalised"))
    shodan_norm = normalise_shodan_domain(Path(shodan_raw), Path("data/normalised"))

    # 3. combine sources
    combined = combine_normalised_sources(
        domain=query,
        vt_path=Path(vt_norm),
        shodan_path=Path(shodan_norm),
        output_dir=Path("data/normalised"),
    )

    # 4. score combined file
    scored_path, scored_json = score_combined_domain(Path(combined))

    # 5. extract features and auto-label
    features = extract_features_from_combined(Path(scored_path))
    label = assign_label_from_features(features)

    # 6. append to dataset
    dataset_path = append_features_to_dataset(
        features=features,
        label=label,
        dataset_path=Path("data/ml/training_data.csv"),
    )

    print(f"Query: {query}")
    print(f"Combined file: {scored_path}")
    print(f"Risk score: {scored_json['risk']['score']}")
    print(f"Risk level: {scored_json['risk']['level']}")
    print("Reasons:")
    for reason in scored_json["risk"]["reasons"]:
        print(f"- {reason}")
    print(f"Auto-assigned label: {label}")
    print(f"Dataset updated: {dataset_path}")


if __name__ == "__main__":
    main()