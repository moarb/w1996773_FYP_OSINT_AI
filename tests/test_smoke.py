from pathlib import Path
import json
import os
import subprocess
import sys

def test_end_to_end_domain_run_creates_outputs():
    # Skip if no API key (so markers don't fail if they don't have one)
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        return

    root = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, "-m", "osint_tool.main", "domain", "bbc.co.uk"]

    result = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    # quick check: at least one report exists
    reports_dir = root / "data" / "reports"
    assert reports_dir.exists()
    assert any(p.suffix == ".md" for p in reports_dir.iterdir())
