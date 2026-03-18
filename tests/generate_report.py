"""Generate the detailed HTML security report and open it in the browser."""
import sys
import os
import subprocess

sys.path.insert(0, "c:/Users/madhu/Projects/Security Helper/security-orch-bot")
os.chdir("c:/Users/madhu/Projects/Security Helper/security-orch-bot")

from app.report_generator import generate_and_save_report

path = generate_and_save_report(
    "20260317_163534_pipeline_DevSecOpsEndtoEnd_cd02b8a9.json",
    build_url="http://localhost:8080/job/DevSecOpsEndtoEnd/18/",
    jenkins_user="admin",
)
print(f"Report saved: {path}")
print(f"\nOpening in browser...")
os.startfile(path)
