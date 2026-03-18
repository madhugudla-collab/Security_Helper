import os
import uuid
import json
import re
import hmac
import hashlib
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Header, Query
from pydantic import BaseModel, Field
from app.agents.orchestrator import orchestrator
from app.github_integration import create_github_pr, push_file_update
from app.mcp_servers.scanner_tool import run_security_scan, detect_language
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv
from app.pipeline_handler import (
    fetch_jenkins_console,
    handle_sast,
    handle_sca,
    handle_container,
    handle_dast,
    handle_iac,
    save_pipeline_report,
)
from app.report_generator import generate_and_save_report
from fastapi.responses import HTMLResponse, FileResponse

load_dotenv()

app = FastAPI(
    title="Security Orchestrator Bot",
    description="AI-powered security vulnerability detection, analysis, and automated PR creation",
    version="2.0.0",
)

# --- Data Models ---
class BuildInfo(BaseModel):
    full_url: str
    log: str

class SecurityFinding(BaseModel):
    vulnerability: str
    code: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    severity: Optional[str] = None  # Critical/High/Medium/Low

class ToolReport(BaseModel):
    tool: str
    findings: SecurityFinding

class JenkinsPayload(BaseModel):
    """Payload sent from Jenkins pipeline on build failure or security scan completion."""
    name: str
    build: BuildInfo
    job_name: str
    build_url: str
    branch: str = "main"
    repo_owner: str = Field(default_factory=lambda: os.getenv("DEFAULT_REPO_OWNER", "madhu-projects"))
    repo_name: str = Field(default_factory=lambda: os.getenv("DEFAULT_REPO_NAME", "vulnerable-app"))
    reports: List[ToolReport]

class OnboardRepoRequest(BaseModel):
    """Request to onboard a new repository for security scanning."""
    repo_owner: str
    repo_name: str
    branch: str = "main"
    language: Optional[str] = None  # auto-detect if not provided
    scan_tools: Optional[List[str]] = None  # auto-select if not provided
    github_url: Optional[str] = None

class ScanRequest(BaseModel):
    """Request to run security scan on a local or cloned repository."""
    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    repo_owner: Optional[str] = None
    repo_name: Optional[str] = None
    branch: str = "main"
    scan_tools: Optional[List[str]] = None
    create_pr: bool = True

# --- Security: Webhook Signature Verification ---
def verify_webhook_signature(payload_body: bytes, signature: str) -> bool:
    """Verify Jenkins/GitHub webhook signature if WEBHOOK_SECRET is set."""
    secret = os.getenv("WEBHOOK_SECRET")
    if not secret:
        return True  # No secret configured, skip verification
    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# --- Helper Functions ---
def sanitize_filename(filename: str) -> str:
    """Prevent path traversal attacks on log file access."""
    clean = os.path.basename(filename)
    clean = re.sub(r'[^a-zA-Z0-9_\-.]', '', clean)
    if not clean or clean.startswith('.'):
        raise ValueError("Invalid filename")
    return clean

def extract_pr_details(ai_text: str):
    """Extracts PR Title and Body from AI analysis."""
    title_match = re.search(r"\[SECURITY\].*", ai_text)
    if not title_match:
        title_match = re.search(r"Title:\s*(.+)", ai_text)
    title = title_match.group(0).strip() if title_match else "[SECURITY] Automated Vulnerability Fix"
    return title, ai_text

def extract_code_fix(ai_text: str) -> Optional[str]:
    """Extracts the code block from the AI response."""
    code_match = re.search(r"```(?:python|java|javascript|go|ruby|typescript)?\n(.*?)```", ai_text, re.DOTALL)
    return code_match.group(1).strip() if code_match else None

def run_security_workflow(data: JenkinsPayload, thread_id: str):
    """Executes the full security analysis and remediation flow."""
    print(f"\n{'='*60}")
    print(f"[Thread: {thread_id}] Starting analysis for {data.job_name}...")
    print(f"Repo: {data.repo_owner}/{data.repo_name} (branch: {data.branch})")
    print(f"Findings: {len(data.reports)} report(s)")
    print(f"{'='*60}\n")

    # 1. Prepare Prompt for AI
    findings_json = json.dumps([r.dict() for r in data.reports], indent=2)
    prompt = (
        f"Security Scan Results for '{data.job_name}' "
        f"(repo: {data.repo_owner}/{data.repo_name}, branch: {data.branch}):\n"
        f"{findings_json}\n\n"
        "Please analyze these findings against SOC2/HIPAA/PCI-DSS policies.\n"
        "For each finding:\n"
        "1. Assess severity and risk\n"
        "2. Provide a specific code fix\n"
        "3. Create a GitHub PR description with title starting with [SECURITY]\n"
        "4. Include compliance impact\n"
    )

    # 2. Invoke Orchestrator (AI Agent)
    config = {"configurable": {"thread_id": thread_id}}
    try:
        result = orchestrator.invoke({"messages": [HumanMessage(content=prompt)]}, config=config)
        analysis = result["messages"][-1].content
        print(f"AI Analysis complete ({len(analysis)} chars)")
    except Exception as e:
        print(f"AI Analysis failed: {e}")
        analysis = f"AI Analysis failed: {str(e)}"

    # 3. Save Report to Disk
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{timestamp}_{data.job_name}_{thread_id[:8]}.json")

    report_payload = {
        "timestamp": timestamp,
        "job_name": data.job_name,
        "build_url": data.build_url,
        "repo": f"{data.repo_owner}/{data.repo_name}",
        "branch": data.branch,
        "thread_id": thread_id,
        "reports": [r.dict() for r in data.reports],
        "status": "completed",
        "ai_analysis": analysis,
        "analyzed_at": datetime.now().isoformat(),
    }

    with open(report_path, "w") as f:
        json.dump(report_payload, f, indent=2)
    print(f"Analysis saved to: {report_path}")

    # 4. Attempt GitHub PR Creation (RESILIENT: push failure does NOT stop PR)
    pr_title, pr_body = extract_pr_details(analysis)
    fixed_code = extract_code_fix(analysis)
    fix_branch = f"fix/{data.job_name}-{timestamp}"

    # Try to push the code fix — failure is non-fatal, PR still created
    code_pushed = False
    if fixed_code and data.reports and data.reports[0].findings.file:
        target_file = data.reports[0].findings.file
        print(f"Pushing fix for {target_file} to branch {fix_branch}...")
        try:
            code_pushed = push_file_update(
                repo_owner=data.repo_owner,
                repo_name=data.repo_name,
                branch_name=fix_branch,
                base_branch=data.branch,
                file_path=target_file,
                new_content=fixed_code,
                commit_message=f"Security fix for {data.reports[0].findings.vulnerability}",
            )
        except Exception as e:
            print(f"Code push failed: {e} -- will still create PR with analysis only")
            code_pushed = False

    # ALWAYS create PR — even if code push failed (PR contains AI analysis)
    print(f"Creating PR on {data.repo_owner}/{data.repo_name}...")
    try:
        # If code push succeeded: head=fix branch, else: use same as base (analysis-only PR)
        pr_head_branch = fix_branch if code_pushed else data.branch
        extra_note = "" if code_pushed else "\n\n> **Note:** Automated code fix could not be pushed. Manual fix required based on the analysis above."
        pr_url = create_github_pr(
            repo_owner=data.repo_owner,
            repo_name=data.repo_name,
            branch_name=pr_head_branch,
            title=pr_title,
            body=pr_body + extra_note,
            base_branch=data.branch,
        )
        if pr_url:
            print(f"PR created: {pr_url}")
        else:
            print("PR creation failed or already exists.")
    except Exception as e:
        print(f"PR creation error: {e}")


# ========================================
# ENDPOINTS
# ========================================

@app.post("/webhook/jenkins", summary="Receive Jenkins security scan results")
async def receive_webhook(
    data: JenkinsPayload,
    background_tasks: BackgroundTasks,
    x_webhook_signature: Optional[str] = Header(None),
):
    """
    Receives security scan results from Jenkins pipeline.
    Triggers AI analysis and automated PR creation in the background.
    """
    print(f"Received Webhook: {data.job_name} ({data.repo_owner}/{data.repo_name})")
    thread_id = str(uuid.uuid4())
    background_tasks.add_task(run_security_workflow, data, thread_id)
    return {
        "status": "processing",
        "thread_id": thread_id,
        "repo": f"{data.repo_owner}/{data.repo_name}",
        "message": "AI Analysis started in background",
    }


@app.post("/scan", summary="Run security scan on a repository")
async def scan_repository(data: ScanRequest, background_tasks: BackgroundTasks):
    """
    Generic endpoint to scan any repository for vulnerabilities.
    Clones the repo (if URL provided), runs scans, then triggers the AI workflow.
    Scanners that are unavailable are skipped gracefully — the flow always continues.
    """
    thread_id = str(uuid.uuid4())
    repo_path = data.repo_path

    # Clone repo if URL provided
    if data.repo_url and not repo_path:
        clone_dir = os.path.join("data", "cloned_repos", thread_id[:8])
        os.makedirs(clone_dir, exist_ok=True)
        repo_path = clone_dir
        os.system(f'git clone --depth 1 -b {data.branch} {data.repo_url} "{clone_dir}"')

    if not repo_path or not os.path.exists(repo_path):
        raise HTTPException(status_code=400, detail="Repository path not found. Provide repo_path or repo_url.")

    # Detect language and select scanners
    language = detect_language(repo_path)
    scan_tools = data.scan_tools or _get_default_scanners(language)

    print(f"Scanning {repo_path} with tools: {scan_tools}")

    # Run scans — RESILIENT: each scanner is independent, failures skip gracefully
    all_findings = []
    scan_summary = {}

    for tool_name in scan_tools:
        try:
            findings = run_security_scan(repo_path, tool_name)
            all_findings.extend(findings)
            scan_summary[tool_name] = {"status": "ok", "findings": len(findings)}
            status_msg = f"{len(findings)} finding(s)" if findings else "clean"
            print(f"  [{tool_name}] {status_msg}")
        except Exception as e:
            # Scanner unavailable (e.g., SonarQube down, tool not installed) — skip and continue
            scan_summary[tool_name] = {"status": "skipped", "reason": str(e)}
            print(f"  [{tool_name}] SKIPPED: {e} -- other scanners continue")

    scanners_ok = [k for k, v in scan_summary.items() if v["status"] == "ok"]
    scanners_skipped = [k for k, v in scan_summary.items() if v["status"] == "skipped"]

    if scanners_skipped:
        print(f"Skipped scanners (unavailable): {scanners_skipped}")
        print(f"Completed scanners: {scanners_ok}")

    if not all_findings:
        return {
            "status": "clean",
            "message": "No vulnerabilities found!",
            "language": language,
            "tools_used": scanners_ok,
            "skipped_tools": scanners_skipped,
        }

    # Convert to JenkinsPayload format and trigger AI workflow
    reports = [
        ToolReport(
            tool=f["tool"],
            findings=SecurityFinding(
                vulnerability=f["vulnerability"],
                file=f.get("file"),
                line=f.get("line"),
                code=f.get("code"),
                severity=f.get("severity"),
            ),
        )
        for f in all_findings
    ]

    payload = JenkinsPayload(
        name="security-scan",
        build=BuildInfo(full_url="local-scan", log="Security scan triggered via API"),
        job_name="security-scan",
        build_url="local-scan",
        branch=data.branch,
        repo_owner=data.repo_owner or os.getenv("DEFAULT_REPO_OWNER", "local"),
        repo_name=data.repo_name or os.path.basename(repo_path),
        reports=reports,
    )

    if data.create_pr:
        background_tasks.add_task(
            _run_scan_individual_prs,
            all_findings, data, language, thread_id,
        )

    return {
        "status": "vulnerabilities_found",
        "thread_id": thread_id,
        "language": language,
        "tools_used": scanners_ok,
        "skipped_tools": scanners_skipped,
        "findings_count": len(all_findings),
        "findings": all_findings[:20],
        "poll_status": f"http://localhost:8000/scan/status/{thread_id}",
        "message": "AI analysis started — poll /scan/status/{thread_id} for PRs" if data.create_pr else "Scan complete",
    }


def _run_scan_individual_prs(findings: list, data: "ScanRequest", language: str, thread_id: str):
    """
    Create one GitHub PR per unique vulnerability type from local scanner findings.
    Groups findings by rule/type, applies AI fix to each affected file, creates PR.
    """
    from collections import defaultdict
    from app.pipeline_handler import (
        _gh_create_branch, _gh_fetch_file, _gh_push_file,
        _ai_fix_source_code, _openai_analyze, _gh_headers,
    )

    token = os.getenv("GITHUB_TOKEN", "")
    repo_owner = data.repo_owner or os.getenv("DEFAULT_REPO_OWNER", "local")
    repo_name = data.repo_name or "scanned-repo"
    branch = data.branch

    if not token:
        print("[Scan] GITHUB_TOKEN not set — skipping PR creation")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Group HIGH/CRITICAL findings by vulnerability type
    type_groups: dict = defaultdict(list)
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        if sev in ("HIGH", "CRITICAL"):
            vuln_key = re.sub(r"[^a-z0-9]+", "-",
                              f.get("vulnerability", "unknown").lower())[:40].strip("-")
            type_groups[vuln_key].append(f)

    # Sort by count, cap at 6 PRs per scan
    sorted_groups = sorted(type_groups.items(), key=lambda x: -len(x[1]))[:6]
    print(f"[Scan] Creating {len(sorted_groups)} individual PR(s) for {language} repo...")

    prs_created = []
    issues_created = []

    for vuln_slug, vuln_findings in sorted_groups:
        display = vuln_findings[0].get("vulnerability", vuln_slug)[:60]
        branch_name = f"fix/security/{vuln_slug}-{timestamp[:13].replace('_','-')}"
        print(f"\n[Scan] ▶ {display} ({len(vuln_findings)} findings)")

        if not _gh_create_branch(repo_owner, repo_name, branch_name, branch, token):
            continue

        # Group by file, fix each
        file_groups: dict = defaultdict(list)
        for f in vuln_findings:
            if f.get("file"):
                file_groups[f["file"]].append(f)

        files_fixed = 0
        file_details = []

        for file_path, file_findings in list(file_groups.items())[:3]:
            src, sha = _gh_fetch_file(repo_owner, repo_name, file_path, branch, token)
            if not src:
                continue
            fixed = _ai_fix_source_code(src, file_path, file_findings, language=language)
            if not fixed or fixed.strip() == src.strip():
                continue
            _, branch_sha = _gh_fetch_file(repo_owner, repo_name, file_path, branch_name, token)
            if _gh_push_file(repo_owner, repo_name, branch_name, file_path, fixed,
                             branch_sha or sha,
                             f"[Security Bot] Fix {display}: {file_path.split('/')[-1]}", token):
                files_fixed += 1
                lines = [str(f.get("line", "?")) for f in file_findings]
                file_details.append(f"`{file_path}` (lines {', '.join(lines)})")
                print(f"[Scan] ✅ Fixed: {file_path}")

        # If no code fix, push analysis markdown
        if files_fixed == 0:
            md = (
                f"# Security Analysis: {display}\n\n"
                f"**Tool:** {vuln_findings[0].get('tool','scanner')} | **Language:** {language}\n"
                f"**Findings:** {len(vuln_findings)}\n\n"
                f"## Affected Locations\n\n"
                + "\n".join(f"- `{f.get('file','')}` line {f.get('line','?')}: {f.get('vulnerability','')}"
                             for f in vuln_findings)
                + "\n"
            )
            _gh_push_file(repo_owner, repo_name, branch_name,
                          f"security-reports/scan-{vuln_slug}-{timestamp[:13]}.md",
                          md, None, f"[Security Bot] Security analysis: {display}", token)

        # AI analysis for PR body
        analysis = _openai_analyze(
            f"Vulnerability: {display}\nLanguage: {language}\n"
            f"Findings: {json.dumps(vuln_findings[:5], indent=2)}\n\n"
            f"Provide: 1) Root cause 2) Exact code fix 3) Compliance impact (SOC2/OWASP/PCI-DSS)",
            max_tokens=800,
        )

        pr_body = f"## 🔐 [SECURITY-FIX] {display}\n\n"
        pr_body += f"| Field | Value |\n|---|---|\n"
        pr_body += f"| **Tool** | {vuln_findings[0].get('tool','scanner')} |\n"
        pr_body += f"| **Language** | {language} |\n"
        pr_body += f"| **Severity** | {vuln_findings[0].get('severity','HIGH')} |\n"
        pr_body += f"| **Findings** | {len(vuln_findings)} |\n"
        pr_body += f"| **Files Fixed** | {files_fixed} |\n\n"
        pr_body += "### 📍 Affected Locations\n\n"
        for f in vuln_findings[:10]:
            pr_body += f"- `{f.get('file','?')}` line **{f.get('line','?')}**: {f.get('vulnerability','')}\n"
        pr_body += f"\n### 🔧 Fix\n\n"
        if file_details:
            pr_body += "Automated fixes applied to:\n" + "".join(f"- {d}\n" for d in file_details)
        pr_body += f"\n### 🤖 AI Analysis\n\n{analysis}\n"
        pr_body += "\n---\n*Security Orchestrator Bot — Do NOT auto-merge without review.*\n"

        try:
            pr_url = create_github_pr(
                repo_owner=repo_owner, repo_name=repo_name,
                branch_name=branch_name,
                title=f"[SECURITY-FIX] Fix for {display}",
                body=pr_body, base_branch=branch,
            )
            if pr_url:
                prs_created.append({"type": "SCAN", "vuln": display, "url": pr_url})
                print(f"[Scan] ✅ PR: {pr_url}")
        except Exception as e:
            print(f"[Scan] PR failed: {e}")

    # Save scan report — include ALL findings so the HTML report can render them
    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "data", "security_reports")
    os.makedirs(report_dir, exist_ok=True)
    report_file = f"{timestamp}_scan_{repo_name}_{thread_id[:8]}.json"
    report_path = os.path.join(report_dir, report_file)

    # Build severity summary
    sev_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        sev_summary[sev] = sev_summary.get(sev, 0) + 1

    # Build per-PR AI analysis
    pr_analysis = []
    for pr in prs_created:
        pr_analysis.append({
            "vuln": pr.get("vuln", ""),
            "url": pr.get("url", ""),
            "type": pr.get("type", "SCAN"),
            "files_fixed": pr.get("files_fixed", 0),
        })

    with open(report_path, "w") as f:
        json.dump({
            "timestamp": timestamp,
            "thread_id": thread_id,
            "repo": f"{repo_owner}/{repo_name}",
            "language": language,
            "findings_count": len(findings),
            "severity_summary": sev_summary,
            "prs_created": prs_created,
            "pr_analysis": pr_analysis,
            "job_name": f"scan-{repo_name}",
            # Save ALL findings for HTML report
            "all_findings": findings[:200],  # cap at 200 for file size
        }, f, indent=2)

    html_report_url = f"http://localhost:8000/report/scan?scan_file={report_file}"
    print("\n" + "═" * 65)
    print("  ✅  SCAN COMPLETE — ALL DONE")
    print("═" * 65)
    print(f"  Findings : {len(findings)}  |  PRs Created: {len(prs_created)}")
    print(f"  Language : {language.upper()}")
    for pr in prs_created:
        print(f"  🔀 PR    : {pr['url']}")
    print()
    print(f"  📊 HTML REPORT  ➜  {html_report_url}")
    print(f"  📄 Raw JSON     ➜  http://localhost:8000/logs/{report_file}")
    print("═" * 65)


@app.get("/scan/status/{thread_id}", summary="Check /scan job completion")
def check_scan_status(thread_id: str):
    """Poll this after calling POST /scan — returns done+PRs once analysis completes."""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    if not os.path.exists(log_dir):
        return {"status": "processing"}
    for fname in sorted(os.listdir(log_dir), reverse=True):
        if thread_id[:8] in fname and fname.endswith(".json") and "scan_" in fname:
            with open(os.path.join(log_dir, fname), "r") as f:
                report = json.load(f)
            prs = report.get("prs_created", [])
            html_url = f"http://localhost:8000/report/scan?scan_file={fname}"
            return {
                "status": "done",
                "language": report.get("language"),
                "repo": report.get("repo"),
                "findings_count": report.get("findings_count"),
                "severity_summary": report.get("severity_summary", {}),
                "prs_created": prs,
                "github_prs": [p["url"] for p in prs],
                "html_report_url": html_url,
                "logs_url": f"http://localhost:8000/logs/{fname}",
            }
    return {
        "status": "processing",
        "message": "Scan in progress — AI is fixing vulnerabilities and creating PRs. Check again in 20 seconds.",
    }


@app.post("/onboard", summary="Onboard a new repository for security scanning")
async def onboard_repo(data: OnboardRepoRequest):
    """
    Onboard any repository for security scanning.
    Returns a Jenkinsfile and webhook configuration for the repo.
    """
    github_url = data.github_url or f"https://github.com/{data.repo_owner}/{data.repo_name}"
    language = data.language or "auto"
    scan_tools = data.scan_tools or _get_default_scanners(language)

    jenkinsfile = _generate_jenkinsfile(
        repo_owner=data.repo_owner,
        repo_name=data.repo_name,
        branch=data.branch,
        scan_tools=scan_tools,
        language=language,
    )

    return {
        "status": "onboarded",
        "repo": f"{data.repo_owner}/{data.repo_name}",
        "github_url": github_url,
        "language": language,
        "scan_tools": scan_tools,
        "jenkinsfile": jenkinsfile,
        "webhook_url": "/webhook/jenkins",
        "instructions": [
            f"1. Add the Jenkinsfile to {data.repo_owner}/{data.repo_name}",
            "2. Configure Jenkins pipeline pointing to the repo",
            "3. Set webhook URL in Jenkins to point to this server's /webhook/jenkins endpoint",
            "4. Ensure GITHUB_TOKEN is set in the bot's .env file",
            "5. Run the pipeline - on security findings, a PR will be auto-created",
        ],
    }


@app.get("/logs", summary="List all security reports")
def list_logs():
    """List all saved security analysis reports."""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    if not os.path.exists(log_dir):
        return []
    return sorted(os.listdir(log_dir), reverse=True)


@app.get("/logs/{filename}", summary="View a specific security report")
def get_log(filename: str):
    """View a specific security analysis report."""
    try:
        clean_name = sanitize_filename(filename)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")

    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    filepath = os.path.join(log_dir, clean_name)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")

    with open(filepath, "r") as f:
        return json.load(f)


@app.get("/status/{thread_id}", summary="Check if bot analysis is complete")
def check_status(thread_id: str):
    """
    Poll this endpoint after calling /webhook/jenkins/pipeline.
    Returns 'processing' until the report is saved, then returns 'done' with all links.
    Use the thread_id returned from the webhook response.
    """
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    if not os.path.exists(log_dir):
        return {"status": "processing", "message": "Report not yet available"}

    # Find report file that contains this thread_id
    for fname in sorted(os.listdir(log_dir), reverse=True):
        if thread_id[:8] in fname and fname.endswith(".json") and "pipeline" in fname:
            fpath = os.path.join(log_dir, fname)
            with open(fpath, "r") as f:
                report = json.load(f)
            prs = report.get("prs_created", [])
            alerts = report.get("alerts_generated", [])
            html_reports = [
                f"http://localhost:8000/report/generate?pipeline_file={fname}"
            ]
            return {
                "status": "done",
                "report_file": fname,
                "job_name": report.get("job_name"),
                "build_url": report.get("build_url"),
                "summary": {
                    "sast":      report.get("sast", {}).get("status", "unknown"),
                    "sca":       f"{report.get('sca', {}).get('findings_count', 0)} findings",
                    "container": f"{report.get('container', {}).get('findings_count', 0)} CVEs",
                    "dast":      f"{report.get('dast', {}).get('findings_count', 0)} alerts",
                    "iac":       f"{report.get('iac', {}).get('findings_count', 0)} findings",
                },
                "prs_created":     prs,
                "alerts_created":  alerts,
                "html_report_url": html_reports[0],
                "logs_url":        f"http://localhost:8000/logs/{fname}",
                "github_issues": [a["url"] for a in alerts],
                "github_prs":    [p["url"] for p in prs],
            }

    return {
        "status": "processing",
        "thread_id": thread_id,
        "message": "Analysis in progress — AI is reading Jenkins console log and creating GitHub Issues/PRs. Check again in 30 seconds.",
        "tip": "Watch the bot terminal for live progress logs",
    }


@app.get("/report/scan", summary="Generate HTML report for /scan results", response_class=HTMLResponse)
def generate_scan_report(
    scan_file: str = Query(..., description="Scan report filename (from /logs, ends with _scan_*.json)"),
):
    """
    Generate a beautiful HTML report for a /scan job result.
    Shows: severity dashboard, all findings, GitHub PRs created, AI decision logic, compliance impact.
    Printable as PDF via File → Print → Save as PDF.
    """
    try:
        clean = sanitize_filename(scan_file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")

    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    path = os.path.join(report_dir, clean)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Scan report not found: {clean}")

    from app.report_generator import generate_scan_html_report
    html = generate_scan_html_report(path)
    return HTMLResponse(content=html)


@app.get("/report/generate", summary="Generate detailed HTML security report", response_class=HTMLResponse)
def generate_report(
    pipeline_file: str = Query(..., description="Pipeline report filename from /logs"),
    build_url: str = Query(default="http://localhost:8080/job/DevSecOpsEndtoEnd/18/"),
    jenkins_user: str = Query(default="admin"),
):
    """
    Generate a detailed HTML security report for a pipeline run.
    Shows per-scan-type: findings, AI decision logic, why action taken / not taken, compliance impact.
    Printable as PDF via File → Print → Save as PDF.
    """
    try:
        clean = sanitize_filename(pipeline_file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename")

    report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "security_reports")
    path = os.path.join(report_dir, clean)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Pipeline report not found")

    from app.report_generator import generate_html_report
    html = generate_html_report(path, build_url=build_url, jenkins_user=jenkins_user)
    return HTMLResponse(content=html)


@app.get("/health", summary="Health check")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "github_configured": bool(os.getenv("GITHUB_TOKEN")),
        "openai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "sonarqube_configured": bool(os.getenv("SONARQUBE_TOKEN")),
    }


# --- Internal Helpers ---
def _get_default_scanners(language: str) -> List[str]:
    """
    Return default security scanners based on detected language.

    SonarQube is ALWAYS FIRST — it is the primary scanner for all languages.
    If SonarQube is unavailable (token missing, project not found, server down),
    it returns [] and the next scanner takes over gracefully.

    Language-specific tools follow as supplementary scanners.
    """
    scanner_map = {
        # Java  — SonarQube (primary) + Semgrep java rules + SpotBugs (needs Maven)
        "java":       ["sonarqube", "semgrep", "spotbugs"],

        # Python — SonarQube (primary) + Bandit (fast, accurate) + Safety (deps) + Semgrep
        "python":     ["sonarqube", "bandit", "safety", "semgrep"],

        # JavaScript/TypeScript — SonarQube + npm-audit (deps) + Semgrep
        "javascript": ["sonarqube", "semgrep", "npm-audit"],
        "typescript": ["sonarqube", "semgrep", "npm-audit"],

        # Go — SonarQube + Semgrep go rules (gosec not always installed)
        "go":         ["sonarqube", "semgrep"],

        # Ruby — SonarQube + Semgrep ruby rules (brakeman for Rails apps)
        "ruby":       ["sonarqube", "semgrep"],

        # PHP — SonarQube + Semgrep
        "php":        ["sonarqube", "semgrep"],

        # C# — SonarQube + Semgrep
        "csharp":     ["sonarqube", "semgrep"],

        # Unknown language — try SonarQube then Semgrep auto
        "auto":       ["sonarqube", "semgrep"],
    }
    return scanner_map.get(language, ["sonarqube", "semgrep"])


def _generate_jenkinsfile(repo_owner: str, repo_name: str, branch: str, scan_tools: List[str], language: str) -> str:
    """Generate a Jenkinsfile for the given repository configuration."""

    scan_stages = ""
    for tool_name in scan_tools:
        if tool_name == "bandit":
            scan_stages += f"""
        stage('SAST - Bandit') {{
            steps {{
                sh 'pip install bandit'
                sh 'bandit -r . -f json -o bandit-report.json || true'
            }}
        }}"""
        elif tool_name == "semgrep":
            scan_stages += f"""
        stage('SAST - Semgrep') {{
            steps {{
                sh 'pip install semgrep'
                sh 'semgrep --config=auto --json --output=semgrep-report.json . || true'
            }}
        }}"""
        elif tool_name == "safety":
            scan_stages += f"""
        stage('SCA - Safety') {{
            steps {{
                sh 'pip install safety'
                sh 'safety check --json > safety-report.json || true'
            }}
        }}"""
        elif tool_name == "npm-audit":
            scan_stages += f"""
        stage('SCA - npm audit') {{
            steps {{
                sh 'npm audit --json > npm-audit-report.json || true'
            }}
        }}"""
        elif tool_name == "trivy":
            scan_stages += f"""
        stage('Container Scan - Trivy') {{
            steps {{
                sh 'trivy fs --format json --output trivy-report.json . || true'
            }}
        }}"""
        elif tool_name == "sonarqube":
            scan_stages += f"""
        stage('SAST - SonarQube') {{
            steps {{
                withSonarQubeEnv('SonarQube') {{
                    sh 'sonar-scanner -Dsonar.projectKey={repo_name} || true'
                }}
            }}
        }}"""
        elif tool_name == "spotbugs":
            scan_stages += f"""
        stage('SAST - SpotBugs') {{
            steps {{
                sh 'mvn compile spotbugs:spotbugs || true'
            }}
        }}"""

    return f"""pipeline {{
    agent any

    environment {{
        REPO_OWNER = '{repo_owner}'
        REPO_NAME = '{repo_name}'
        SECURITY_BOT_URL = '${{env.SECURITY_BOT_URL ?: "http://localhost:8000"}}'
    }}

    stages {{
        stage('Checkout') {{
            steps {{
                checkout scm
            }}
        }}{scan_stages}

        stage('Collect Results') {{
            steps {{
                script {{
                    def findings = []
                    def reportFiles = findFiles(glob: '*-report.json')
                    reportFiles.each {{ reportFile ->
                        def report = readJSON file: reportFile.name
                        findings.add([
                            tool: reportFile.name.replace('-report.json', ''),
                            findings: [
                                vulnerability: "Security issues found in ${{reportFile.name}}",
                                file: reportFile.name
                            ]
                        ])
                    }}
                    env.SCAN_FINDINGS = groovy.json.JsonOutput.toJson(findings)
                }}
            }}
        }}
    }}

    post {{
        always {{
            script {{
                def payload = [
                    name: env.JOB_NAME,
                    job_name: env.JOB_NAME,
                    build_url: env.BUILD_URL,
                    branch: '{branch}',
                    repo_owner: env.REPO_OWNER,
                    repo_name: env.REPO_NAME,
                    build: [
                        full_url: env.BUILD_URL,
                        log: currentBuild.result ?: 'SUCCESS'
                    ],
                    reports: readJSON(text: env.SCAN_FINDINGS ?: '[]')
                ]

                httpRequest(
                    url: "${{env.SECURITY_BOT_URL}}/webhook/jenkins",
                    httpMode: 'POST',
                    contentType: 'APPLICATION_JSON',
                    requestBody: groovy.json.JsonOutput.toJson(payload)
                )
            }}
        }}
    }}
}}
"""


# ========================================
# ENHANCED DEVSECOPS PIPELINE ENDPOINT
# New endpoint — does NOT modify existing /webhook/jenkins behavior
# ========================================

class DevSecOpsPipelinePayload(BaseModel):
    """
    Enhanced payload for the full DevSecOps pipeline webhook.
    Reads the Jenkins console log and routes findings to different handlers:
      SAST (SonarQube)  -> Creates GitHub PR with AI code fix
      SCA (Snyk)        -> Creates GitHub PR (dep upgrade) or GitHub Issue alert
      Container (Trivy) -> Creates GitHub Issue alert
      DAST (ZAP)        -> Saves structured security report + GitHub Issue for HIGH findings
      IaC (Checkov)     -> Creates GitHub PR with Terraform fix
    """
    build_url: str                                        # e.g. http://localhost:8080/job/DevSecOpsEndtoEnd/18/
    job_name: str                                         # e.g. DevSecOpsEndtoEnd
    repo_owner: str                                       # GitHub owner
    repo_name: str                                        # GitHub repo name
    branch: str = "main"
    sonarqube_project_key: Optional[str] = None          # e.g. "easybuggy"
    sonarqube_url: str = "http://localhost:9000"          # SonarQube host
    zap_report_path: Optional[str] = None                # Override ZAP report path
    jenkins_workspace: Optional[str] = None              # e.g. C:\ProgramData\Jenkins\.jenkins\workspace\DevSecOpsEndtoEnd
    jenkins_url: str = "http://localhost:8080"
    jenkins_user: str = "admin"
    jenkins_token: Optional[str] = None                  # Jenkins API token (if different from password)


def run_devsecops_pipeline_workflow(data: DevSecOpsPipelinePayload, thread_id: str):
    """
    Full DevSecOps pipeline handler.
    Reads Jenkins console log → routes each scan type to appropriate action.
    All scan handlers are independent — one failure does NOT stop others.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"\n{'='*60}")
    print(f"[DevSecOps Pipeline] {data.job_name} -> {data.repo_owner}/{data.repo_name}")
    print(f"Build: {data.build_url}")
    print(f"{'='*60}\n")

    report = {
        "timestamp": timestamp,
        "thread_id": thread_id,
        "job_name": data.job_name,
        "build_url": data.build_url,
        "repo": f"{data.repo_owner}/{data.repo_name}",
        "sast": {},
        "sca": {},
        "container": {},
        "dast": {},
        "iac": {},
        "prs_created": [],
        "alerts_generated": [],
    }

    # 1. Fetch Jenkins console log (used by SCA, Container, IaC parsers)
    console_text = ""
    try:
        console_text = fetch_jenkins_console(
            build_url=data.build_url,
            user=data.jenkins_user,
            token=data.jenkins_token,
        )
    except Exception as e:
        print(f"[Pipeline] Console fetch failed: {e} — parsers will work with empty text")

    # 2. SAST — SonarQube API -> PR
    try:
        handle_sast(data, report, timestamp)
    except Exception as e:
        print(f"[SAST] Handler error: {e}")
        report["sast"]["status"] = "error"

    # 3. SCA — Snyk console -> PR or Issue
    try:
        handle_sca(data, console_text, report, timestamp)
    except Exception as e:
        print(f"[SCA] Handler error: {e}")
        report["sca"]["status"] = "error"

    # 4. Container — Trivy console -> Issue alert
    try:
        handle_container(data, console_text, report, timestamp)
    except Exception as e:
        print(f"[Container] Handler error: {e}")
        report["container"]["status"] = "error"

    # 5. DAST — ZAP HTML report -> structured report + Issue
    try:
        handle_dast(data, report, timestamp)
    except Exception as e:
        print(f"[DAST] Handler error: {e}")
        report["dast"]["status"] = "error"

    # 6. IaC — Checkov console -> PR
    try:
        handle_iac(data, console_text, report, timestamp)
    except Exception as e:
        print(f"[IaC] Handler error: {e}")
        report["iac"]["status"] = "error"

    # 7. Save full pipeline report
    save_pipeline_report(report, data, thread_id, timestamp)

    print(f"\n[Pipeline] Done! PRs: {len(report['prs_created'])} | Alerts: {len(report['alerts_generated'])}")
    for pr in report["prs_created"]:
        print(f"  PR [{pr['type']}]: {pr['url']}")
    for alert in report["alerts_generated"]:
        print(f"  Alert [{alert['type']}]: {alert['url']}")


@app.post("/webhook/jenkins/pipeline", summary="Enhanced DevSecOps full pipeline webhook")
async def receive_devsecops_pipeline(
    data: DevSecOpsPipelinePayload,
    background_tasks: BackgroundTasks,
):
    """
    Enhanced webhook for a full DevSecOps pipeline (SonarQube + Snyk + Trivy + ZAP + Checkov).

    Actions per scan type:
    - SAST (SonarQube)  -> GitHub PR with AI code fix
    - SCA (Snyk)        -> GitHub PR for dependency upgrade, or GitHub Issue alert
    - Container (Trivy) -> GitHub Issue alert (cannot auto-fix OS-level CVEs)
    - DAST (ZAP)        -> Structured JSON report + GitHub Issue for HIGH findings
    - IaC (Checkov)     -> GitHub PR with Terraform fix

    Update Jenkins post-build to call this endpoint instead of /webhook/jenkins.
    """
    thread_id = str(uuid.uuid4())
    background_tasks.add_task(run_devsecops_pipeline_workflow, data, thread_id)
    return {
        "status": "processing",
        "thread_id": thread_id,
        "job": data.job_name,
        "repo": f"{data.repo_owner}/{data.repo_name}",
        "message": "DevSecOps pipeline analysis started. SAST->PR, SCA->PR/Alert, Container->Alert, DAST->Report, IaC->PR",
    }
