# Demo script for IPD
# Run from project root. Assumes venv activated and dependencies installed.

$env:PYTHONPATH = "src"

python -m osint_tool.main domain bbc.co.uk

Write-Host ""
Write-Host "Check outputs in:"
Write-Host "  data/raw"
Write-Host "  data/normalised"
Write-Host "  data/reports"
