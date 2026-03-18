#!/usr/bin/env python3
import json, os, sys

f = "data/security_reports/20260318_003130_scan_devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo_9b4829b5.json"
with open(f) as fh:
    d = json.load(fh)

print("Keys:", list(d.keys()))
print("findings_count:", d.get("findings_count"))
print("severity_summary:", d.get("severity_summary"))
print("language:", d.get("language"))
print("prs_created count:", len(d.get("prs_created", [])))
print("all_findings count:", len(d.get("all_findings", [])))
if d.get("all_findings"):
    print("First finding:", json.dumps(d["all_findings"][0], indent=2))
else:
    print("NO all_findings in JSON — old format before the fix")
    print("Full JSON structure:")
    print(json.dumps(d, indent=2)[:3000])
