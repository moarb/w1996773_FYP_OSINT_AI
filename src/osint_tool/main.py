import sys
from pathlib import Path

from osint_tool.pipeline.collect import collect_from_virustotal
from osint_tool.pipeline.normalise import normalise_virustotal_domain
from osint_tool.pipeline.score import score_normalised_domain
from osint_tool.pipeline.report import generate_markdown_report


def main():
    if len(sys.argv) != 3:
        print("Usage: python -m osint_tool.main <type> <query>")
        sys.exit(1)

    query_type = sys.argv[1]
    query = sys.argv[2]


    # Phase 1: Collect raw data
    raw_path = collect_from_virustotal(query_type, query)
    print(f"Raw data saved to: {raw_path}")


    # Phase 2: Normalise data
    normalised_path = normalise_virustotal_domain(
        raw_path=Path(raw_path),
        output_dir=Path("data/normalised")
    )

    print(f"Normalised data saved to: {normalised_path}")


    # Phase 3: Score risk
    scored_path, scored_json = score_normalised_domain(Path(normalised_path))
    print(f"Scored data saved to: {scored_path}")
    print(f"Risk: {scored_json['risk']['level']} ({scored_json['risk']['score']})")


    # Phase 4: Generate report
    report_path = generate_markdown_report(
        scored_path=Path(normalised_path),
        output_dir=Path("data/reports")
    )
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()