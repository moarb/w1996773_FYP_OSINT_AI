import os
import sys
from pathlib import Path
import streamlit as st

# Build the path to the src folder so Streamlit can import project modules correctly
SRC_PATH = Path(__file__).resolve().parents[1] / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

# Import the main orchestration function for analysing a domain
from osint_tool.pipeline.analyse import analyse_domain

# Configure the Streamlit page
st.set_page_config(page_title="AI-Assisted OSINT Tool", layout="wide")

# Display the main title and short description
st.title("AI-Assisted OSINT Risk Analysis Tool")
st.caption("Multi-source prototype using VirusTotal + Shodan, with rule-based scoring and ML-assisted prediction.")

# Tell the user what input type is currently supported
st.info("Current supported query type: domain")

# Input field where the user enters a domain
domain = st.text_input("Enter domain", value="", placeholder="e.g. bbc.co.uk")

# Button that triggers the full analysis
run = st.button("Run Analysis")

if run:
    # Remove any accidental whitespace from the user input
    query = domain.strip()

    # Prevent the analysis from running on an empty input
    if not query:
        st.error("Please enter a domain.")
        st.stop()

    try:
        # Show a loading spinner while the full pipeline runs
        with st.spinner("Running full analysis pipeline..."):
            result = analyse_domain(query)

        # Extract the rule-based and ML outputs so they can be compared
        rule_level = result["rule_level"]
        ml_prediction = result["ml_prediction"]
        agreement = "Yes" if rule_level == ml_prediction else "No"

        st.success("Analysis complete.")

        # Display the top-level summary metrics
        st.markdown("## Final Assessment")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Rule-based score", f"{result['rule_score']} / 100")
        col2.metric("Rule-based level", rule_level)
        col3.metric("ML prediction", ml_prediction)
        col4.metric("Rule / ML agreement", agreement)

        # Display the explanation for why the score/result was produced
        st.markdown("## Why this result?")
        for reason in result["reasons"]:
            st.write(f"- {reason}")

        # Display the source-specific summaries from VirusTotal and Shodan
        st.markdown("## Source Summary")

        vt = result["source_summary"]["virustotal"]
        shodan = result["source_summary"]["shodan"]

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("### VirusTotal")
            st.write(f"**Reputation:** {vt['reputation']}")
            st.write(f"**Malicious:** {vt['malicious']}")
            st.write(f"**Suspicious:** {vt['suspicious']}")
            st.write(f"**Harmless:** {vt['harmless']}")
            st.write(f"**Undetected:** {vt['undetected']}")

        with col_b:
            st.markdown("### Shodan")
            st.write(f"**Resolved IP:** {shodan['resolved_ip']}")
            st.write(f"**Open port count:** {shodan['open_port_count']}")
            st.write(f"**Open ports:** {shodan['open_ports']}")
            st.write(f"**Vulnerability count:** {shodan['vulns_count']}")
            st.write(f"**Risky port exposed:** {shodan['has_risky_port']}")
            st.write(f"**CDN detected:** {shodan['is_cdn']}")

        # Display a human-readable summary sentence
        st.markdown("## Short Summary")
        st.write(result["summary_text"])

        # Show where the markdown report was saved
        st.markdown("## Report")
        st.write(f"**Saved to:** `{result['report_path']}`")

        # Attempt to load the generated report file and preview it
        try:
            report_text = Path(result["report_path"]).read_text(encoding="utf-8")
            st.text_area("Markdown report preview", report_text, height=300)
        except Exception as e:
            st.warning(f"Could not load report preview: {e}")

        # Display the extracted feature dictionary for transparency
        st.markdown("## Extracted Features")
        st.json(result["features"])

    except Exception as e:
        # If the pipeline fails, show an error message and the exception details
        st.error("Analysis failed.")
        st.exception(e)