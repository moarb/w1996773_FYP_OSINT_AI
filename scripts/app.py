import os
import sys
import json
from pathlib import Path

import streamlit as st

# Ensure Python can import from src if you run via `streamlit run`
SRC_PATH = Path(__file__).resolve().parents[1] / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from osint_tool.pipeline.collect import collect_from_virustotal
from osint_tool.pipeline.normalise import normalise_virustotal_domain
from osint_tool.pipeline.score import score_normalised_domain
from osint_tool.pipeline.report import generate_markdown_report

st.set_page_config(page_title="AI-Assisted OSINT Tool (Prototype)", layout="centered")

st.title("AI-Assisted OSINT Tool (Prototype)")
st.caption("VirusTotal → normalise → risk scoring → report generation")

st.markdown("### Run a scan")

query_type = st.selectbox("Query type", ["Domain"])
st.caption("Prototype currently supports VirusTotal domain scans only (IPD scope).")
query = st.text_input("Target (e.g. bbc.co.uk)")

run = st.button("Run scan")

def _safe_read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

if run:
    if not query.strip():
        st.error("Please enter a target.")
        st.stop()

    try:
        with st.spinner("Collecting OSINT data..."):
            raw_path = collect_from_virustotal(query_type, query)

        with st.spinner("Normalising data..."):
            norm_path = normalise_virustotal_domain(
                raw_path=Path(raw_path),
                output_dir=Path("data/normalised"),
            )

        with st.spinner("Scoring risk..."):
            scored_path, risk_obj = score_normalised_domain(Path(norm_path))

        # IMPORTANT: re-load scored file to ensure UI uses the actual saved schema
        scored_data = _safe_read_json(Path(scored_path))
        risk_obj = (scored_data.get("risk") or {}) if isinstance(scored_data, dict) else {}

        with st.spinner("Generating report..."):
            report_path = generate_markdown_report(Path(scored_path), Path("data/reports"))

        st.success("Done.")

        st.markdown("### Result")

        risk_level = risk_obj.get("level") or "N/A"
        risk_score = risk_obj.get("score")
        risk_score = 0 if risk_score is None else risk_score
        reasons = risk_obj.get("reasons") or []

        st.metric("Risk level", str(risk_level))
        st.metric("Risk score", f"{int(risk_score)} / 100")

        st.markdown("**Reasons:**")
        if reasons:
            for r in reasons:
                st.write(f"- {r}")
        else:
            st.write("- (no reasons recorded)")

        st.markdown("### Files created")
        st.code(
            f"Raw: {raw_path}\nNormalised: {norm_path}\nScored: {scored_path}\nReport: {report_path}",
            language="text",
        )

        st.markdown("### Report preview")
        try:
            report_text = Path(report_path).read_text(encoding="utf-8")
            st.text_area("Markdown report", report_text, height=260)
        except Exception as e:
            st.warning(f"Could not load report preview: {e}")

    except Exception as e:
        st.error("Something went wrong while running the pipeline.")
        st.exception(e)
