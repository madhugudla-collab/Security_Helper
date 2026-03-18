#!/usr/bin/env python3
"""Generate HTML report for AWSGoat scan."""
import sys
sys.path.insert(0, ".")
from app.report_generator import generate_scan_html_report

scan_file = "data/security_reports/20260318_101606_scan_AWSGoat_e367ed6f.json"
html = generate_scan_html_report(scan_file)

output = "data/security_reports/scan_report_AWSGoat_e367ed6f.html"
with open(output, "w", encoding="utf-8") as f:
    f.write(html)

print(f"Report saved: {output}")
print(f"Size: {len(html)//1024} KB")
print()
print("Sections check:")
checks = [
    ("Severity Dashboard",   "Severity Dashboard"),
    ("Scanner Results",      "Scanner Results"),
    ("GitHub PRs",           "Pull Requests Created"),
    ("AI Decision Logic",    "AI Decision Logic"),
    ("Findings table",       "sev sev-"),
    ("Compliance Impact",    "Compliance Impact"),
    ("Threat Model",         "Threat Model"),
    ("Application Summary",  "Application Summary"),
    ("Entry Points",         "Entry Points"),
    ("STRIDE Mitigations",   "MITIGATIONS"),
]
ok = 0
for name, key in checks:
    present = key in html
    status = "OK  " if present else "MISS"
    if present:
        ok += 1
    print(f"  {status} | {name}")

print(f"\nResult: {ok}/{len(checks)} sections present")
print(f"\nView report: http://localhost:8000/report/scan?scan_file=20260318_101606_scan_AWSGoat_e367ed6f.json")
print(f"Or open file: {output}")
