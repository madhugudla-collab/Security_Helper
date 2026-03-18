"""
Test the full DevSecOps pipeline endpoint against Jenkins build #18
"""
import time
import requests

BOT_URL = "http://localhost:8000"

def run_test():
    # 1. Trigger the pipeline
    r = requests.post(f"{BOT_URL}/webhook/jenkins/pipeline", json={
        "build_url": "http://localhost:8080/job/DevSecOpsEndtoEnd/18/",
        "job_name": "DevSecOpsEndtoEnd",
        "repo_owner": "madhugudla-collab",
        "repo_name": "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
        "branch": "main",
        "sonarqube_project_key": "easybuggy",
        "sonarqube_url": "http://localhost:9000",
        "jenkins_user": "admin",
        "jenkins_workspace": "C:/ProgramData/Jenkins/.jenkins/workspace/DevSecOpsEndtoEnd"
    }, timeout=15)
    print(f"Status: {r.status_code}")
    resp = r.json()
    print(f"Thread: {resp.get('thread_id')}")
    print(f"Message: {resp.get('message')}")

    # 2. Wait for processing (AI analysis + GitHub)
    print("\nWaiting 90s for AI analysis + GitHub operations...")
    time.sleep(90)

    # 3. Read results
    logs = requests.get(f"{BOT_URL}/logs", timeout=5).json()
    pipeline_reports = [l for l in logs if "pipeline" in l]
    if not pipeline_reports:
        print("No pipeline report found!")
        return

    d = requests.get(f"{BOT_URL}/logs/{pipeline_reports[0]}", timeout=5).json()

    print()
    print("=" * 50)
    print("  DEVSECOPS PIPELINE RESULTS")
    print("=" * 50)
    print(f"  SAST (SonarQube) : {d.get('sast',{}).get('status','?')} - {d.get('sast',{}).get('findings_count','N/A')} findings")
    print(f"  SCA  (Snyk)      : {d.get('sca',{}).get('status','?')} - {d.get('sca',{}).get('findings_count','N/A')} findings")
    print(f"  Container(Trivy) : {d.get('container',{}).get('status','?')} - {d.get('container',{}).get('findings_count','N/A')} CVEs")
    print(f"  DAST (ZAP)       : {d.get('dast',{}).get('status','?')} - {d.get('dast',{}).get('findings_count','N/A')} alerts")
    print(f"  IaC  (Checkov)   : {d.get('iac',{}).get('status','?')} - {d.get('iac',{}).get('findings_count','N/A')} findings")
    print()
    prs = d.get("prs_created", [])
    alerts = d.get("alerts_generated", [])
    print(f"  PRs created    : {len(prs)}")
    for pr in prs:
        print(f"    [{pr['type']}] {pr['url']}")
    print(f"  Alerts created : {len(alerts)}")
    for alert in alerts:
        print(f"    [{alert['type']}] {alert['url']}")
    print("=" * 50)

if __name__ == "__main__":
    run_test()
