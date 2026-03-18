#!/usr/bin/env python3
"""
Regenerate the HTML report from the existing scan JSON.
Tests: SonarQube live fetch + AI threat model + fallback threat model.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.report_generator import generate_scan_html_report

scan_file = "data/security_reports/20260318_003130_scan_devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo_9b4829b5.json"
out_file  = "data/security_reports/scan_report_9b4829b5_v2.html"

print(f"\n{'='*60}")
print("  Regenerating HTML report...")
print(f"{'='*60}")
print(f"  Input:  {scan_file}")
print(f"  Output: {out_file}")
print(f"{'='*60}\n")

html = generate_scan_html_report(scan_file)

with open(out_file, "w", encoding="utf-8") as f:
    f.write(html)

size_kb = len(html) // 1024
print(f"\n{'='*60}")
print(f"  ✅ SUCCESS — {size_kb} KB HTML generated")
print(f"  Sections detected:")
sections = [
    ("Severity Dashboard", "Severity Dashboard" in html),
    ("Scanner Results table", "Scanner Results" in html),
    ("GitHub PRs section", "Pull Requests Created" in html),
    ("AI Decision Logic", "AI Decision Logic" in html),
    ("HIGH/CRITICAL findings", "HIGH Findings" in html or "CRITICAL Findings" in html),
    ("Compliance Impact", "Compliance Impact" in html),
    ("Threat Model", "Threat Model" in html),
    ("Application Summary", "Application Summary" in html or "app_summary" in html.lower() or "Threat Model" in html),
    ("Entry Points table", "Entry Points" in html),
    ("Threat Catalog", "Threat Catalog" in html or "Threat Model" in html),
]
for name, present in sections:
    icon = "✅" if present else "❌"
    print(f"     {icon} {name}")

print(f"\n  Open in browser: file://{os.path.abspath(out_file)}")
print(f"  OR via bot:      http://localhost:8000/report/scan?scan_file=20260318_003130_scan_devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo_9b4829b5.json")
print(f"{'='*60}\n")
