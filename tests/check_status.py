import json, requests, glob, os

report_dir = "data/security_reports"
# Find the scan report
files = sorted(glob.glob(f"{report_dir}/*9b4829b5*.json"), reverse=True)
if files:
    with open(files[0]) as f:
        rpt = json.load(f)
    print("=== SCAN REPORT ===")
    print(f"Findings: {rpt.get('findings_count')}")
    print(f"Language: {rpt.get('language')}")
    prs = rpt.get("prs_created", [])
    print(f"PRs created: {len(prs)}")
    for pr in prs:
        print(f"  [{pr.get('type')}] {str(pr.get('vuln',''))[:55]}")
        print(f"     -> {pr.get('url')}")
else:
    print("No report file found")

# Poll status
try:
    r = requests.get(
        "http://localhost:8000/scan/status/9b4829b5-fdf2-4586-a8a1-5fadb841286c",
        timeout=5
    )
    print("\n=== STATUS ENDPOINT ===")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Status endpoint error: {e}")
