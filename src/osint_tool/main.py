import sys
from osint_tool.pipeline.analyse import analyse_domain


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python -m osint_tool.main domain <query>")
        sys.exit(1)

    query_type = sys.argv[1].strip().lower()
    query = sys.argv[2].strip()

    if query_type != "domain":
        raise ValueError("This unified version currently supports domain analysis only.")

    result = analyse_domain(query)

    print("\nFinal Analysis Result:\n")
    print(f"Domain: {result['domain']}")
    print(f"Rule-based score: {result['rule_score']}")
    print(f"Rule-based level: {result['rule_level']}")
    print(f"ML prediction: {result['ml_prediction']}")
    print(f"ML confidence: {result['ml_confidence']:.2f}")
    print(f"Report path: {result['report_path']}")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")


if __name__ == "__main__":
    main()