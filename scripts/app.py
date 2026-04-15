import os
import sys
from pathlib import Path
import streamlit as st

SRC_PATH = Path(__file__).resolve().parents[1] / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from osint_tool.pipeline.analyse import analyse_domain

st.set_page_config(page_title="AI-Assisted OSINT Tool", layout="wide")

st.title("AI-Assisted OSINT Risk Analysis Tool")
st.caption("Multi-source prototype using VirusTotal + Shodan, with rule-based scoring and ML-assisted prediction.")

st.info("Current supported query type: domain")

domain = st.text_input("Enter domain", value="", placeholder="e.g. bbc.co.uk")

run = st.button("Run Analysis")

if run:
    query = domain.strip()

    if not query:
        st.error("Please enter a domain.")
        st.stop()

    try:
        with st.spinner("Running full analysis pipeline..."):
            result = analyse_domain(query)

        rule_level = result["rule_level"]
        ml_prediction = result["ml_prediction"]
        agreement = "Yes" if rule_level == ml_prediction else "No"

        st.success("Analysis complete.")

        st.markdown("## Final Assessment")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Rule-based score", f"{result['rule_score']} / 100")
        col2.metric("Rule-based level", rule_level)
        col3.metric("ML prediction", ml_prediction)
        col4.metric("Rule / ML agreement", agreement)

        st.markdown("## Why this result?")
        for reason in result["reasons"]:
            st.write(f"- {reason}")

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

        st.markdown("## Short Summary")
        st.write(result["summary_text"])

        st.markdown("## Report")
        st.write(f"**Saved to:** `{result['report_path']}`")

        try:
            report_text = Path(result["report_path"]).read_text(encoding="utf-8")
            st.text_area("Markdown report preview", report_text, height=300)
        except Exception as e:
            st.warning(f"Could not load report preview: {e}")

        st.markdown("## Extracted Features")
        st.json(result["features"])

    except Exception as e:
        st.error("Analysis failed.")
        st.exception(e)