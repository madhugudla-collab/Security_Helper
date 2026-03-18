#!/usr/bin/env python3
"""
Security Scan Runner
================================
Quick one-command scan for any repository.

Usage:
  python tests/run_interview_scan.py
  python tests/run_interview_scan.py --build-url http://localhost:8080/job/DevSecOpsEndtoEnd/28/
  python tests/run_interview_scan.py --repo-owner myorg --repo-name their-repo --sonar-project myproject

What it does:
  1. Triggers the Security Orchestrator Bot on the latest Jenkins build
  2. Waits for analysis to complete (polls every 10s)
  3. Prints a clean summary with ALL GitHub PR links
  4. Prints the REPORT URL in big text so you can share it immediately
"""

import argparse
import requests
import os
import sys
import time
import subprocess
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

BOT_URL = "http://localhost:8000"
JENKINS_URL = "http://localhost:8080"


def get_latest_jenkins_build(job_name: str = "DevSecOpsEndtoEnd") -> str:
    """Get the URL of the latest Jenkins build."""
    try:
        r = requests.get(
            f"{JENKINS_URL}/job/{job_name}/api/json",
            auth=("admin", "admin"), timeout=10,
        )
        if r.status_code == 200:
            build_num = r.json()["lastBuild"]["number"]
            url = f"{JENKINS_URL}/job/{job_name}/{build_num}"
            print(f"  Latest Jenkins build: #{build_num} → {url}")
            return url
    except Exception as e:
        print(f"  Jenkins not reachable: {e}")
    return f"{JENKINS_URL}/job/{job_name}/lastBuild"


def trigger_bot(args, build_url: str) -> bool:
    """Send the webhook payload to the Security Bot."""
    payload = {
        "build_url": build_url,
        "job_name": args.job_name,
        "repo_owner": args.repo_owner,
        "repo_name": args.repo_name,
        "branch": args.branch,
        "jenkins_user": "admin",
        "jenkins_workspace": "",
        "sonarqube_url": args.sonar_url,
        "sonarqube_project_key": args.sonar_project,
    }
    try:
        r = requests.post(f"{BOT_URL}/webhook/jenkins/pipeline", json=payload, timeout=30)
        if r.status_code == 200:
            print(f"  ✅ Bot triggered: {r.json().get('message','OK')}")
            return True
        print(f"  ❌ Bot error: {r.status_code} — {r.text[:200]}")
    except Exception as e:
        print(f"  ❌ Cannot reach bot at {BOT_URL}: {e}")
        print(f"     Make sure the bot is running: cd security-orch-bot && python -m uvicorn app.main:app --reload")
    return False


def wait_for_report(args, max_wait: int = 600) -> tuple:
    """Poll bot /logs until a new pipeline report appears. Returns (filename, report_dict)."""
    print(f"\n  ⏳ Waiting for analysis (max {max_wait}s)...")
    start = time.time()
    seen = set()

    # Snapshot existing reports
    try:
        r = requests.get(f"{BOT_URL}/logs", timeout=10)
        if r.status_code == 200:
            seen = {f for f in r.json() if "pipeline_" in f and args.job_name in f}
    except Exception:
        pass

    while time.time() - start < max_wait:
        time.sleep(10)
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] Checking for completed report...", end="\r")
        try:
            r = requests.get(f"{BOT_URL}/logs", timeout=10)
            if r.status_code != 200:
                continue
            all_files = r.json()
            new_pipeline = [
                f for f in all_files
                if "pipeline_" in f and args.job_name in f and f not in seen
            ]
            if new_pipeline:
                latest = sorted(new_pipeline)[-1]
                rr = requests.get(f"{BOT_URL}/logs/{latest}", timeout=10)
                if rr.status_code == 200:
                    report = rr.json()
                    if (report.get("prs_created") or report.get("alerts_generated") or
                            report.get("sast", {}).get("findings_count", 0) > 0):
                        print(f"\n  ✅ Report ready: {latest}")
                        return latest, report
        except Exception:
            pass

    print(f"\n  ⚠️  Timed out after {max_wait}s")
    return None, None


def print_results(filename: str, report: dict):
    """Print a clean summary with all PR/Issue links and the report URL."""
    sast = report.get("sast", {})
    sca = report.get("sca", {})
    container = report.get("container", {})
    iac = report.get("iac", {})
    prs = report.get("prs_created", [])
    issues = report.get("alerts_generated", [])

    print("\n" + "═" * 70)
    print("  🛡️   DEVSECOPS SECURITY SCAN — RESULTS SUMMARY")
    print("═" * 70)
    print(f"\n  {'SCAN':<18} {'TOOL':<12} {'FINDINGS':>10}   STATUS")
    print(f"  {'─'*18} {'─'*12} {'─'*10}   {'─'*20}")
    print(f"  {'SAST':<18} {'SonarQube':<12} {sast.get('findings_count',0):>10}   "
          f"{'✅ ' + str(sast.get('pr_count',0)) + ' PR(s)' if sast.get('pr_count',0) else sast.get('status','?')}")
    print(f"  {'SCA':<18} {'Snyk':<12} {sca.get('findings_count',0):>10}   "
          f"{'✅ PR created' if sca.get('pr_url') else 'Issue created' if sca.get('alert_url') else sca.get('status','?')}")
    print(f"  {'Container':<18} {'Trivy':<12} {container.get('findings_count',0):>10}   "
          f"{'✅ Issue created' if container.get('alert_url') else container.get('status','?')}")
    print(f"  {'IaC':<18} {'Checkov':<12} {iac.get('findings_count',0):>10}   "
          f"{'✅ PR created' if iac.get('pr_url') else 'Issue created' if iac.get('alert_url') else iac.get('status','?')}")
    print(f"  {'DAST':<18} {'OWASP ZAP':<12} {report.get('dast',{}).get('findings_count',0):>10}   "
          f"{report.get('dast',{}).get('status','?')}")

    print(f"\n{'─' * 70}")
    print(f"  🔀 GitHub Pull Requests ({len(prs)} created):")
    if prs:
        for pr in prs:
            rule = pr.get("rule", "")
            rule_label = f" [{rule}]" if rule else ""
            print(f"     [{pr['type']}]{rule_label}  {pr['url']}")
    else:
        print("     (none)")

    print(f"\n  📌 GitHub Issues ({len(issues)} created):")
    if issues:
        for iss in issues:
            print(f"     [{iss['type']}]  {iss['url']}")
    else:
        print("     (none)")

    # SAST individual PRs
    individual_prs = sast.get("individual_prs", [])
    if individual_prs:
        print(f"\n  🔐 SAST Individual PRs by Vulnerability Type ({len(individual_prs)}):")
        for p in individual_prs:
            files = p.get('files_fixed', 0)
            print(f"     [{p['count']} findings | {files} file(s) fixed]  {p['display']}")
            print(f"       → {p['pr_url']}")

    print("\n" + "═" * 70)
    print("  📋  REPORT URL  — share this link:")
    print()
    report_url = f"{BOT_URL}/report/generate?pipeline_file={filename}"
    print(f"  ➤  {report_url}")
    print()
    print("  To open: copy URL above and paste in browser")
    print("  To save as PDF: Ctrl+P → Save as PDF")
    print("═" * 70)

    # Open report in browser automatically
    try:
        subprocess.Popen(["cmd", "/c", "start", report_url], shell=False)
        print("\n  🌐 Report opened in browser!")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Security Scan Runner — one command to scan, analyze, and create PRs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan latest Jenkins build (default)
  python tests/run_interview_scan.py

  # Scan a specific build
  python tests/run_interview_scan.py --build-url http://localhost:8080/job/DevSecOpsEndtoEnd/28/

  # Scan a different repo
  python tests/run_interview_scan.py \\
    --repo-owner myorg \\
    --repo-name their-vulnerable-app \\
    --sonar-project their-project-key \\
    --job-name SecurityScan
        """
    )
    parser.add_argument("--build-url", help="Jenkins build URL (defaults to latest)")
    parser.add_argument("--repo-owner", default=os.getenv("GITHUB_REPO_OWNER", "madhugudla-collab"))
    parser.add_argument("--repo-name", default=os.getenv("GITHUB_REPO_NAME", "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo"))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--sonar-url", default="http://localhost:9000")
    parser.add_argument("--sonar-project", default=os.getenv("SONARQUBE_PROJECT_KEY", "easybuggy"))
    parser.add_argument("--job-name", default="DevSecOpsEndtoEnd")
    parser.add_argument("--wait", type=int, default=600, help="Max wait time in seconds (default: 600)")
    parser.add_argument("--bot-url", default=BOT_URL)

    args = parser.parse_args()

    print("\n" + "═" * 70)
    print("  🛡️   Security Orchestrator Bot — Scan Runner")
    print("═" * 70)
    print(f"  Repo:      {args.repo_owner}/{args.repo_name}")
    print(f"  Branch:    {args.branch}")
    print(f"  SonarQube: {args.sonar_url} | Project: {args.sonar_project}")
    print(f"  Bot:       {args.bot_url}")

    # Get build URL
    build_url = args.build_url or get_latest_jenkins_build(args.job_name)
    print(f"  Build:     {build_url}")
    print("═" * 70)

    # Trigger bot
    print("\n  🚀 Triggering Security Bot Analysis...")
    if not trigger_bot(args, build_url):
        print("\n  ❌ Failed to trigger bot. Is it running?")
        print(f"     Start with: cd security-orch-bot && python -m uvicorn app.main:app --reload --port 8000")
        sys.exit(1)

    # Wait for report
    filename, report = wait_for_report(args, max_wait=args.wait)

    if not filename or not report:
        print("\n  ❌ No report found. Check bot terminal for errors.")
        print(f"     View logs: {args.bot_url}/logs")
        sys.exit(1)

    # Print results
    print_results(filename, report)


if __name__ == "__main__":
    main()
