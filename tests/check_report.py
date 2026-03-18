#!/usr/bin/env python3
with open("data/security_reports/scan_report_9b4829b5_v2.html", encoding="utf-8") as f:
    html = f.read()

required_checks = [
    ("Severity Dashboard",       "Severity Dashboard"),
    ("Scanner Results",          "Scanner Results"),
    ("GitHub PRs",               "Pull Requests Created"),
    ("AI Decision Logic",        "AI Decision Logic"),
    ("Findings table",           "sev sev-"),
    ("Compliance Impact",        "Compliance Impact"),
    ("Threat Model header",      "Threat Model"),
    ("Application Summary",      "Application Summary"),
    ("Entry Points",             "Entry Points"),
    ("Important Assets",         "Important Assets"),
    ("Threat Catalog",           "Threat Catalog"),
    ("STRIDE mitigations",       "MITIGATIONS"),
    ("PR links in HTML",         "github.com"),
]
optional_checks = [
    ("AWS Controls (optional)",  "AWS Controls"),
]

print()
ok = fail = 0
for name, key in required_checks:
    present = key in html
    status = "OK     " if present else "MISSING"
    if present: ok += 1
    else: fail += 1
    print(f"  {status} | {name}")
for name, key in optional_checks:
    present = key in html
    status = "OK     " if present else "N/A    "
    print(f"  {status} | {name}")
print(f"\n  Required: {ok}/{len(required_checks)} ✅  {'FAIL: '+str(fail)+' missing' if fail else 'ALL PASS'}")

print()
print("Total HTML size:", len(html) // 1024, "KB")

# Show first 200 chars of Threat Model section
idx = html.find("Threat Model")
if idx >= 0:
    print("\nThreat Model preview:")
    print(html[idx:idx+300])
