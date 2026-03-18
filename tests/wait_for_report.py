"""
Wait for Security Bot Analysis to Complete
===========================================
Run this AFTER triggering a Jenkins build.
It will poll the /status endpoint every 15 seconds and tell you when the report is ready.

Usage:
    python tests/wait_for_report.py <thread_id>

OR run without a thread_id to track the latest pipeline report:
    python tests/wait_for_report.py

The thread_id is printed by the bot terminal when Jenkins calls the webhook.
"""

import sys
import time
import requests
import os

BOT_URL = "http://localhost:8000"


def wait_for_latest_report(max_wait_seconds=120):
    """Poll /logs until a new pipeline report appears, then open the HTML report."""
    print(f"\n{'='*55}")
    print("  Security Bot — Waiting for Analysis to Complete")
    print(f"{'='*55}")
    print(f"  Polling every 15s (max {max_wait_seconds}s)")
    print("  Bot terminal shows live progress\n")

    # Get current list of reports to detect NEW ones
    try:
        before = set(requests.get(f"{BOT_URL}/logs", timeout=5).json())
    except Exception:
        before = set()

    start = time.time()
    attempt = 0

    while time.time() - start < max_wait_seconds:
        attempt += 1
        elapsed = int(time.time() - start)
        print(f"  [{elapsed:3d}s] Checking... (attempt {attempt})", end="\r")

        try:
            current = set(requests.get(f"{BOT_URL}/logs", timeout=5).json())
            new_reports = [f for f in (current - before) if "pipeline" in f and f.endswith(".json")]

            if new_reports:
                latest = sorted(new_reports, reverse=True)[0]
                print(f"\n\n  ✅ ANALYSIS COMPLETE!")
                print(f"  Report: {latest}\n")

                # Fetch and display the report summary
                d = requests.get(f"{BOT_URL}/logs/{latest}", timeout=5).json()
                print(f"  {'='*50}")
                print(f"  DEVSECOPS PIPELINE RESULTS")
                print(f"  {'='*50}")
                print(f"  Job:        {d.get('job_name')}")
                print(f"  Build:      {d.get('build_url')}")
                print(f"  {'='*50}")

                sast = d.get("sast", {})
                sca = d.get("sca", {})
                container = d.get("container", {})
                dast = d.get("dast", {})
                iac = d.get("iac", {})

                print(f"  SAST (SonarQube) : {sast.get('status','?')} — {sast.get('findings_count', sast.get('reason', 'N/A'))}")
                print(f"  SCA  (Snyk)      : {sca.get('status','?')} — {sca.get('findings_count','N/A')} findings")
                print(f"  Container(Trivy) : {container.get('status','?')} — {container.get('findings_count','N/A')} CVEs")
                print(f"  DAST (ZAP)       : {dast.get('status','?')} — {dast.get('findings_count','N/A')} alerts")
                print(f"  IaC  (Checkov)   : {iac.get('status','?')} — {iac.get('findings_count','N/A')} findings")
                print(f"  {'='*50}")

                prs = d.get("prs_created", [])
                alerts = d.get("alerts_generated", [])

                if prs:
                    print(f"\n  🔀 GitHub PRs Created ({len(prs)}):")
                    for pr in prs:
                        print(f"     [{pr['type']}] {pr['url']}")

                if alerts:
                    print(f"\n  📌 GitHub Issues Created ({len(alerts)}):")
                    for alert in alerts:
                        print(f"     [{alert['type']}] {alert['url']}")

                report_url = f"{BOT_URL}/report/generate?pipeline_file={latest}&build_url={d.get('build_url','')}"
                print(f"\n  📊 HTML Report URL:")
                print(f"     {report_url}")
                print(f"\n  → Opening HTML report in browser...")
                os.startfile(report_url) if sys.platform == "win32" else os.system(f"open '{report_url}'")
                return True

        except Exception as e:
            print(f"\n  Bot not responding: {e} — retrying...")

        time.sleep(15)

    print(f"\n  ⏱ Timeout after {max_wait_seconds}s — bot may still be processing")
    print(f"  Check manually: {BOT_URL}/logs")
    return False


def wait_for_thread(thread_id: str, max_wait_seconds=120):
    """Poll /status/{thread_id} until the report is done."""
    print(f"\n{'='*55}")
    print("  Security Bot — Waiting for Analysis to Complete")
    print(f"{'='*55}")
    print(f"  Thread ID: {thread_id}")
    print(f"  Polling {BOT_URL}/status/{thread_id[:8]}...")
    print(f"  Max wait: {max_wait_seconds}s\n")

    start = time.time()
    attempt = 0

    while time.time() - start < max_wait_seconds:
        attempt += 1
        elapsed = int(time.time() - start)
        print(f"  [{elapsed:3d}s] Checking... (attempt {attempt})", end="\r")

        try:
            r = requests.get(f"{BOT_URL}/status/{thread_id}", timeout=5)
            data = r.json()

            if data.get("status") == "done":
                print(f"\n\n  ✅ ANALYSIS COMPLETE!\n")
                summary = data.get("summary", {})
                print(f"  {'='*50}")
                print(f"  DEVSECOPS PIPELINE RESULTS")
                print(f"  {'='*50}")
                print(f"  SAST (SonarQube) : {summary.get('sast','?')}")
                print(f"  SCA  (Snyk)      : {summary.get('sca','?')}")
                print(f"  Container(Trivy) : {summary.get('container','?')}")
                print(f"  DAST (ZAP)       : {summary.get('dast','?')}")
                print(f"  IaC  (Checkov)   : {summary.get('iac','?')}")
                print(f"  {'='*50}")

                issues = data.get("github_issues", [])
                prs    = data.get("github_prs", [])

                if prs:
                    print(f"\n  🔀 GitHub PRs ({len(prs)}):")
                    for url in prs:
                        print(f"     {url}")
                if issues:
                    print(f"\n  📌 GitHub Issues ({len(issues)}):")
                    for url in issues:
                        print(f"     {url}")

                html_url = data.get("html_report_url", "")
                print(f"\n  📊 Full HTML Report:")
                print(f"     {html_url}")
                print(f"\n  → Opening in browser...")
                os.startfile(html_url) if sys.platform == "win32" else os.system(f"open '{html_url}'")
                return True

        except Exception as e:
            print(f"\n  Error: {e} — retrying...")

        time.sleep(15)

    print(f"\n  ⏱ Timeout after {max_wait_seconds}s")
    return False


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Thread ID provided — poll /status/{thread_id}
        wait_for_thread(sys.argv[1], max_wait_seconds=180)
    else:
        # No thread ID — watch for any new pipeline report
        wait_for_latest_report(max_wait_seconds=180)
