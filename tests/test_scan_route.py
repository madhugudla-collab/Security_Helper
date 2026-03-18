#!/usr/bin/env python3
"""
Test POST /scan  — the "no Jenkins" scenario.

Sends a GitHub repo URL to the bot. Bot:
  1. Clones the repo
  2. Auto-detects language (Python / JS / Java / Go / Ruby / TS / PHP / C#)
  3. Runs appropriate local scanners (Bandit, Semgrep, Safety, etc.)
  4. Groups HIGH/CRITICAL findings by vulnerability type
  5. Creates ONE GitHub PR per vulnerability type with language-specific AI fix
  6. Polls /scan/status/{thread_id} until done

Usage:
  python tests/test_scan_route.py
  python tests/test_scan_route.py --repo-url https://github.com/OWASP/WebGoat --repo-owner OWASP --repo-name WebGoat
"""

import argparse
import requests
import time
import sys
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

BOT_URL = "http://localhost:8000"

# A well-known deliberately vulnerable Python repo for testing
DEFAULT_REPO_URL   = "https://github.com/madhugudla-collab/devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo"
DEFAULT_REPO_OWNER = os.getenv("GITHUB_REPO_OWNER", "madhugudla-collab")
DEFAULT_REPO_NAME  = os.getenv("GITHUB_REPO_NAME", "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo")


def test_scan(args):
    print("\n" + "═" * 65)
    print("  🛡️   Security Bot — POST /scan  (No-Jenkins Mode)")
    print("═" * 65)
    print(f"  Repo URL:  {args.repo_url}")
    print(f"  Owner:     {args.repo_owner}  |  Name: {args.repo_name}")
    print(f"  Branch:    {args.branch}")
    print("═" * 65)

    # ── Step 1: Trigger the scan ──────────────────────────────────
    payload = {
        "repo_url":   args.repo_url,
        "repo_owner": args.repo_owner,
        "repo_name":  args.repo_name,
        "branch":     args.branch,
        "create_pr":  True,
    }

    print("\n  🚀 Triggering POST /scan ...")
    try:
        r = requests.post(f"{BOT_URL}/scan", json=payload, timeout=60)
    except Exception as e:
        print(f"  ❌ Cannot reach bot: {e}")
        print(f"     Start it: cd security-orch-bot && python -m uvicorn app.main:app --reload")
        sys.exit(1)

    if r.status_code != 200:
        print(f"  ❌ HTTP {r.status_code}: {r.text[:300]}")
        sys.exit(1)

    resp = r.json()
    thread_id = resp.get("thread_id", "")
    language  = resp.get("language", "?")
    n_found   = resp.get("findings_count", 0)
    tools_ok  = resp.get("tools_used", [])
    tools_skip = resp.get("skipped_tools", [])

    print(f"\n  ✅ Scan started!")
    print(f"     Thread:    {thread_id}")
    print(f"     Language:  {language}")
    print(f"     Findings:  {n_found}")
    print(f"     Scanners:  {tools_ok}  (skipped: {tools_skip})")

    if n_found == 0:
        print("\n  ✅ CLEAN — no vulnerabilities found!")
        return

    # Show first few findings
    findings = resp.get("findings", [])
    if findings:
        print(f"\n  Top findings (showing first {min(5, len(findings))}):")
        for f in findings[:5]:
            sev = f.get("severity", "?")
            vuln = f.get("vulnerability", "")[:60]
            file_ = f.get("file", "")
            line = f.get("line", "?")
            print(f"     [{sev}] {vuln}  ({file_}:{line})")

    # ── Step 2: Poll /scan/status/{thread_id} ──────────────────────
    poll_url = f"{BOT_URL}/scan/status/{thread_id}"
    print(f"\n  ⏳ Polling {poll_url} for PRs...")

    start = time.time()
    while time.time() - start < args.wait:
        time.sleep(15)
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] Checking...", end="\r")

        try:
            sr = requests.get(poll_url, timeout=10)
            sd = sr.json()
        except Exception:
            continue

        if sd.get("status") == "done":
            print(f"\n\n  ✅ Analysis complete!")
            prs = sd.get("prs_created", [])
            sev = sd.get("severity_summary", {})
            html_report = sd.get("html_report_url", "")

            # Severity summary
            if sev:
                print(f"\n  📊 Severity Breakdown:")
                print(f"     🔴 CRITICAL: {sev.get('CRITICAL', 0)}")
                print(f"     🟠 HIGH:     {sev.get('HIGH', 0)}")
                print(f"     🟡 MEDIUM:   {sev.get('MEDIUM', 0)}")
                print(f"     🟢 LOW:      {sev.get('LOW', 0)}")

            # PRs
            print(f"\n  🔀 GitHub PRs created ({len(prs)}):")
            if prs:
                for pr in prs:
                    vuln = pr.get("vuln", pr.get("type", ""))
                    url  = pr.get("url", "")
                    print(f"     [{pr.get('type','SCAN')}] {vuln}")
                    print(f"       → {url}")
            else:
                print("     (none — check bot terminal for errors)")

            # HTML Report link — the KEY output
            print()
            print("  " + "━" * 61)
            print("  📊  HTML SECURITY REPORT (open in browser):")
            print(f"  ➜   {html_report}")
            print("  " + "━" * 61)
            print(f"\n  📄 Raw JSON: {sd.get('logs_url', '')}")
            break
    else:
        print(f"\n  ⚠️  Timed out — but scan may still be running.")
        print(f"     Check manually: {poll_url}")
        # Try to get the report URL anyway
        try:
            sr = requests.get(poll_url, timeout=5)
            sd = sr.json()
            if sd.get("html_report_url"):
                print()
                print("  " + "━" * 61)
                print("  📊  HTML REPORT (may still be generating PRs):")
                print(f"  ➜   {sd['html_report_url']}")
                print("  " + "━" * 61)
        except Exception:
            pass

    print("\n" + "═" * 65)
    print("  SUMMARY")
    print("═" * 65)
    print(f"  Language detected:  {language}")
    print(f"  Scanners used:      {tools_ok}")
    print(f"  Total findings:     {n_found}")
    print(f"  Poll URL:           {poll_url}")
    print("═" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test POST /scan — no Jenkins needed, just a GitHub URL"
    )
    parser.add_argument("--repo-url",   default=DEFAULT_REPO_URL)
    parser.add_argument("--repo-owner", default=DEFAULT_REPO_OWNER)
    parser.add_argument("--repo-name",  default=DEFAULT_REPO_NAME)
    parser.add_argument("--branch",     default="main")
    parser.add_argument("--wait",       type=int, default=300,
                        help="Max seconds to poll for PRs (default: 300)")
    args = parser.parse_args()
    test_scan(args)
