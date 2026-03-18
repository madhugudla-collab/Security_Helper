# 🛡️ Security Orchestrator Bot v2.0
### AI-Powered DevSecOps Security Analysis & Automated Remediation

> **Interview Quick Summary:** This bot takes a GitHub repo URL → scans it for vulnerabilities → creates GitHub PRs with AI-generated fixes → generates a full HTML report with a Threat Model. Zero Jenkins required for the interview demo.

---

## 📋 Table of Contents
1. [What This Project Does](#-what-this-project-does)
2. [Project Folder Structure](#-project-folder-structure)
3. [Architecture Diagram](#-architecture-diagram)
4. [Data Flow — Input to Output](#-data-flow--input-to-output)
5. [How to Start the Program](#-how-to-start-the-program)
6. [How to Run a Security Scan](#-how-to-run-a-security-scan)
7. [How to View & Share the Report](#-how-to-view--share-the-report)
8. [Key API Endpoints](#-key-api-endpoints)
9. [Environment Variables](#-environment-variables)
10. [Interview Demo Walkthrough](#-interview-demo-walkthrough)

---

## 🎯 What This Project Does

The Security Orchestrator Bot is a **FastAPI application** that acts as an AI security analyst:

| Step | What Happens |
|------|-------------|
| 1️⃣ **Input** | You give it a GitHub repo URL (e.g. `https://github.com/org/repo`) |
| 2️⃣ **Scan** | It clones the repo and runs security scanners (SonarQube, Semgrep, Bandit, Safety, etc.) |
| 3️⃣ **Analyze** | GPT-4o-mini analyzes findings against OWASP/PCI-DSS/SOC2 policies |
| 4️⃣ **Fix** | AI generates language-specific code fixes and creates GitHub Pull Requests |
| 5️⃣ **Report** | Generates a full HTML report with severity dashboard, all findings, and **AWS Threat Composer-style Threat Model** |

**Two modes of operation:**
- 🚀 **No-Jenkins mode** — Give it any GitHub URL, it scans locally in ~2 minutes
- 🔧 **Jenkins mode** — Reads Jenkins pipeline logs, creates PRs/Issues for SAST/SCA/IaC/Container/DAST findings

---

## 📁 Project Folder Structure

```
security-orch-bot/
│
├── 📄 README.md                    ← You are here
├── 📄 INTERVIEW_QUICK_GUIDE.md     ← Quick cheat sheet for the interview
├── 📄 Jenkinsfile                  ← Jenkins pipeline (SAST+SCA+IaC+Container+DAST)
├── 📄 requirements.txt             ← Python dependencies
├── 📄 .env                         ← 🔑 API keys (NOT committed to git)
├── 📄 .env.example                 ← Template for .env
│
├── 📂 app/                         ← CORE APPLICATION
│   ├── main.py                     ← FastAPI app + all HTTP endpoints (/scan, /webhook, /report)
│   ├── pipeline_handler.py         ← Handles Jenkins webhook payloads → triggers analysis
│   ├── github_integration.py       ← GitHub API: create PR, create branch, push files
│   ├── report_generator.py         ← HTML report generator (pipeline + scan reports)
│   │
│   ├── 📂 agents/                  ← AI AGENT LAYER
│   │   ├── orchestrator.py         ← LangGraph orchestrator — routes findings to agents
│   │   ├── code_fix_agents.py      ← AI code fix generator (per language: Java/Python/JS/Go)
│   │   ├── codex_tool.py           ← OpenAI API wrapper for code generation
│   │   └── state.py                ← Shared state schema for LangGraph
│   │
│   ├── 📂 mcp_servers/             ← MCP TOOL SERVERS
│   │   ├── scanner_tool.py         ← Local security scanner runner (Bandit/Semgrep/Safety/etc.)
│   │   └── github_tool.py          ← GitHub MCP tool (fetch file content, PR operations)
│   │
│   └── 📂 rag/                     ← RAG (Retrieval-Augmented Generation)
│       ├── engine.py               ← FAISS vector search for security policy docs
│       ├── drive_loader.py         ← Loads PDF docs into vector store
│       └── data/                   ← Security PDFs (OWASP, AWS, Agentic AI)
│
├── 📂 tests/                       ← TEST SCRIPTS
│   ├── test_scan_route.py          ← 🎯 MAIN TEST: POST /scan + poll for PRs + show report URL
│   ├── run_interview_scan.py       ← One-click interview demo script
│   ├── check_status.py             ← Check /scan/status/{thread_id}
│   ├── generate_report.py          ← Generate HTML report from saved JSON
│   ├── regen_report.py             ← Regenerate report with live SonarQube data
│   ├── check_report.py             ← Verify all sections present in HTML report
│   ├── check_sonar_projects.py     ← Debug SonarQube project key lookup
│   ├── inspect_scan.py             ← Inspect saved scan JSON structure
│   ├── test_sonar.py               ← Test SonarQube API connectivity
│   ├── test_api.py                 ← Test all API endpoints
│   ├── test_pipeline.py            ← Test Jenkins webhook processing
│   └── wait_for_report.py          ← Wait and poll until report is ready
│
├── 📂 data/                        ← RUNTIME DATA (generated, not committed)
│   ├── security_reports/           ← JSON scan results + HTML reports
│   ├── jenkins_logs/               ← Saved Jenkins console output
│   ├── cloned_repos/               ← Temp cloned repos for scanning
│   └── vector_db/                  ← FAISS vector database (index.faiss + index.pkl)
│
└── 📂 AgentGateway/                ← OPTIONAL: AI Gateway routing (experimental)
    ├── agent-routing.yaml          ← Route rules for agent selection
    ├── security-policy.yaml        ← Security policy definitions
    └── openai-backend.yaml         ← OpenAI backend config
```

---

## 🏗️ Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════╗
║                    SECURITY ORCHESTRATOR BOT v2.0                    ║
╚══════════════════════════════════════════════════════════════════════╝

  ┌─────────────┐    POST /scan        ┌──────────────────────────────┐
  │   You /     │ ──────────────────► │       FastAPI App            │
  │   Jenkins   │   {repo_url,         │       (app/main.py)          │
  │   Webhook   │    branch,           │                              │
  └─────────────┘    create_pr}        └──────────────┬───────────────┘
                                                       │
                     ┌─────────────────────────────────┼──────────────────┐
                     ▼                                 ▼                  ▼
          ┌──────────────────┐            ┌────────────────────┐  ┌──────────────┐
          │  scanner_tool.py │            │  pipeline_handler  │  │ github_integ │
          │  (MCP Server)    │            │  .py               │  │ ration.py    │
          │                  │            │                    │  │              │
          │ • Git clone repo │            │ • Parse Jenkins    │  │ • Create PR  │
          │ • Run Bandit     │            │   console log      │  │ • Push branch│
          │ • Run Semgrep    │            │ • Extract SAST/    │  │ • Create     │
          │ • Run Safety     │            │   SCA/IaC/DAST     │  │   Issue      │
          │ • Run SonarQube  │            │   findings         │  └──────────────┘
          │ • Auto-detect    │            └────────────────────┘         ▲
          │   language       │                        │                   │
          └────────┬─────────┘                        │                   │
                   │                                  │                   │
                   ▼                                  ▼                   │
          ┌──────────────────────────────────────────────────────┐        │
          │               LANGGRAPH ORCHESTRATOR                 │        │
          │               (app/agents/orchestrator.py)           │        │
          │                                                       │        │
          │  findings ──► filter HIGH/CRITICAL ──► group by type │        │
          │                          │                            │        │
          │              for each vuln type:                      │        │
          │                    │                                  │        │
          │                    ▼                                  │        │
          │         ┌─────────────────────┐                      │        │
          │         │  code_fix_agents.py │                      │        │
          │         │  • Fetch source from│                      │        │
          │         │    GitHub           │                      │        │
          │         │  • GPT-4o-mini:     │                      │        │
          │         │    generate fix     │                      │────────┘
          │         │  • Push to branch   │                      │
          │         │  • Create PR        │                      │
          │         └─────────────────────┘                      │
          └─────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
          ┌──────────────────────────────────────────────────────┐
          │               REPORT GENERATOR                        │
          │               (app/report_generator.py)              │
          │                                                       │
          │  1. Fetch 258 findings from SonarQube API            │
          │  2. Severity dashboard (CRITICAL/HIGH/MEDIUM/LOW)    │
          │  3. All findings tables per severity                  │
          │  4. AI Decision Logic explanation                     │
          │  5. Compliance mapping (OWASP/PCI-DSS/SOC2/HIPAA)   │
          │  6. Threat Model (AI-powered, AWS Threat Composer)   │
          │     ├── App Summary + Architecture                   │
          │     ├── Entry Points / Attack Surface                 │
          │     ├── Important Assets / Crown Jewels              │
          │     └── 8+ STRIDE Threats with Mitigations          │
          └──────────────────────────┬───────────────────────────┘
                                     │
                          ┌──────────┴──────────┐
                          ▼                     ▼
               ┌─────────────────┐   ┌──────────────────────┐
               │  JSON Report    │   │  HTML Report (88KB)  │
               │  (saved in      │   │  Viewable in browser │
               │  data/security_ │   │  GET /report/scan    │
               │  reports/)      │   │  ?scan_file=...      │
               └─────────────────┘   └──────────────────────┘
```

---

## 🔄 Data Flow — Input to Output

```
INPUT                    PROCESSING                        OUTPUT
─────                    ──────────                        ──────

GitHub Repo URL          1. Git clone to               GitHub Pull Requests
   │                        data/cloned_repos/             (one per vuln type)
   │                              │                           │
   │                     2. Language detection           GitHub Issues
   │                        (Java/Python/JS/Go)           (for SCA/IaC)
   │                              │                           │
   │                     3. Run scanners:              HTML Report (88KB)
   │                        • SonarQube SAST            │
   │                        • Semgrep rules             │  ┌─ Severity Dashboard
   │                        • Bandit (Python)           │  ├─ 258 Findings Table
   │                        • Safety (deps)             │  ├─ AI Decision Logic
   │                        • SpotBugs (Java)           │  ├─ Compliance Map
   │                              │                     │  └─ Threat Model
   │                     4. AI Filter:                  │      ├─ App Summary
   │                        HIGH+CRITICAL → PR          │      ├─ Entry Points
   │                        MEDIUM → document           │      ├─ Assets
   │                        LOW → monitor               │      └─ STRIDE Threats
   │                              │
   │                     5. For each HIGH/CRIT group:
   │                        • Fetch source from GitHub
   │                        • GPT-4o-mini generates fix
   │                        • Push branch + open PR
   │
   │                     6. Save JSON report
   │                        data/security_reports/
   │                        YYYYMMDD_HHMMSS_scan_{repo}_{id}.json
   │
   └──────────────────────────────────────────────────────────────►
                                                        Reports saved in
                                                        data/security_reports/
```

---

## 🚀 How to Start the Program

### Prerequisites
Make sure these are installed and running:
```
✅ Python 3.11+
✅ SonarQube (http://localhost:9000) — for SAST
✅ Git
✅ Bandit: pip install bandit
✅ Semgrep: pip install semgrep  (or via npm)
✅ Safety: pip install safety
```

### Step 1: Set up environment
```bash
cd "c:\Users\madhu\Projects\Security Helper\security-orch-bot"

# Copy and fill in your API keys
copy .env.example .env
# Edit .env with your keys (see Environment Variables section below)
```

### Step 2: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Start the bot
```bash
# Option A: Development mode (auto-reload on changes)
python -m uvicorn app.main:app --reload --port 8000

# Option B: Production mode
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Step 4: Verify it's running
```bash
# Should return {"status": "ok"}
curl http://localhost:8000/health

# Or open in browser:
# http://localhost:8000/docs    ← Swagger UI with all endpoints
```

---

## 🔍 How to Run a Security Scan

### Method 1: Quick Test Script (Recommended for Interview)
```bash
# Scan the default repo (devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo)
python tests/test_scan_route.py

# Scan a different repo
python tests/test_scan_route.py \
  --repo-url https://github.com/YOUR_ORG/YOUR_REPO \
  --repo-owner YOUR_ORG \
  --repo-name YOUR_REPO \
  --branch main
```

### Method 2: Direct API Call (curl)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/madhugudla-collab/devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
    "repo_owner": "madhugudla-collab",
    "repo_name": "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
    "branch": "main",
    "create_pr": true
  }'
```

### Method 3: One-Click Interview Demo
```bash
python tests/run_interview_scan.py
```

### Poll for Results
After triggering a scan, poll the status endpoint:
```bash
# Replace {thread_id} with the ID returned from POST /scan
curl http://localhost:8000/scan/status/{thread_id}
```

**Response when done:**
```json
{
  "status": "done",
  "findings_count": 118,
  "prs_created": [...],
  "severity_summary": {"CRITICAL": 0, "HIGH": 12, "MEDIUM": 45, "LOW": 61},
  "html_report_url": "http://localhost:8000/report/scan?scan_file=20260318_003130_scan_...json"
}
```

---

## 📊 How to View & Share the Report

### View in Browser (Live)
1. Start the bot (`python -m uvicorn app.main:app --reload`)
2. Open: `http://localhost:8000/report/scan?scan_file=FILENAME.json`
3. The report auto-fetches live SonarQube findings + generates AI threat model

**Example:**
```
http://localhost:8000/report/scan?scan_file=20260318_003130_scan_devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo_9b4829b5.json
```

### View Directly (No Bot Running)
```bash
# Open the pre-generated HTML file directly in browser
start data\security_reports\scan_report_9b4829b5_v2.html
```

### Regenerate Report from Existing JSON
```bash
python tests/regen_report.py
# Output: data/security_reports/scan_report_9b4829b5_v2.html
```

### Export as PDF
1. Open the HTML report in Chrome/Edge
2. Press **Ctrl+P** (Print)
3. Set destination to **"Save as PDF"**
4. Click **Save**

### Share via Email / Slack
1. Open HTML in browser
2. Print → Save as PDF (step above)
3. Share the PDF — it's self-contained with all findings, PRs, and threat model

### Share via GitHub
The HTML report is also available at the GitHub PR URLs created by the bot:
- Each PR contains the AI-generated fix with analysis
- PR description includes the vulnerability details and compliance impact

### List All Available Reports
```bash
# Via API
curl http://localhost:8000/reports

# Or browse the folder directly
ls data/security_reports/*.json
ls data/security_reports/*.html
```

---

## 🔌 Key API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/scan` | POST | Start a new security scan on a GitHub repo |
| `/scan/status/{thread_id}` | GET | Poll scan progress + get report URL |
| `/report/scan` | GET | Generate + serve HTML report (`?scan_file=NAME.json`) |
| `/reports` | GET | List all saved scan reports |
| `/webhook` | POST | Jenkins build webhook (triggers pipeline analysis) |
| `/report/{filename}` | GET | Serve a pre-generated pipeline report |
| `/docs` | GET | Swagger UI — interactive API docs |

---

## 🔑 Environment Variables

Edit `security-orch-bot/.env`:

```bash
# ── REQUIRED ──────────────────────────────────────────────
OPENAI_API_KEY=sk-...            # GPT-4o-mini for AI fixes + threat model
GITHUB_TOKEN=ghp_...             # GitHub PAT (repo: read+write, PR creation)
GITHUB_REPO_OWNER=madhugudla-collab
GITHUB_REPO_NAME=devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo

# ── SONARQUBE ─────────────────────────────────────────────
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=sqa_...          # SonarQube user token
SONARQUBE_PROJECT_KEY=easybuggy  # Override project key (optional)

# ── JENKINS (for webhook mode) ────────────────────────────
JENKINS_URL=http://localhost:8080
JENKINS_USER=admin
JENKINS_TOKEN=...

# ── OPTIONAL ──────────────────────────────────────────────
SNYK_TOKEN=...                   # Snyk SCA scanning
```

---

## 🎤 Interview Demo Walkthrough

### 5-Minute Demo Flow

```
1. Show the architecture (this README)
   "This is a FastAPI bot that scans any GitHub repo for vulnerabilities
    using SonarQube, Semgrep, and other tools, then creates GitHub PRs
    with AI-generated fixes."

2. Start the bot
   > python -m uvicorn app.main:app --reload

3. Trigger a scan
   > python tests/test_scan_route.py
   
   Watch it:
   ✅ Detect language: Java
   ✅ Run scanners: SonarQube → 118 findings
   ✅ AI filters HIGH/CRITICAL
   ✅ Create 6 GitHub PRs with fixes

4. Show GitHub PRs
   Open: https://github.com/madhugudla-collab/devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo/pulls
   Show: AI-generated Java code fixes for path traversal, format string issues, etc.

5. Show the HTML Report
   Open: http://localhost:8000/report/scan?scan_file=20260318_003130_scan_..._9b4829b5.json
   
   Walk through:
   📊 Severity Dashboard (258 findings: HIGH/MEDIUM/LOW)
   🔧 Scanner Results (SonarQube detected as Java)
   🔀 6 GitHub PRs created with AI fixes
   🤖 AI Decision Logic (why HIGH→PR, MEDIUM→document, LOW→monitor)
   🔴 HIGH Findings table (file, line, tool)
   📜 Compliance Impact (PCI-DSS, SOC2, HIPAA, OWASP)
   🔱 Threat Model — AWS Threat Composer Style:
      - App Summary (easybuggy: intentionally vulnerable Java web app)
      - Entry Points (web forms, file upload, URL params)
      - Crown Jewels (user DB, session tokens, admin panel)
      - 8+ STRIDE threats with mitigations

6. For a NEW repo (interviewer gives you one)
   > python tests/test_scan_route.py \
       --repo-url https://github.com/THEIR_ORG/THEIR_REPO \
       --repo-owner THEIR_ORG \
       --repo-name THEIR_REPO

   Bot will: clone → detect language → scan → create PRs → generate report
   Time: ~2-5 minutes
```

### Key Talking Points

| Question | Your Answer |
|----------|-------------|
| "How does it work?" | POST /scan → clone → scan → AI filter → PRs + report |
| "Why GitHub PRs not just a report?" | Developer workflow — they review & merge, no manual copy-paste |
| "How does AI decide what to fix?" | Filters CRITICAL+HIGH only, groups by vuln type, one PR per type |
| "What scanners do you use?" | SonarQube (SAST), Semgrep (rules), Bandit (Python), Safety (deps), SpotBugs (Java) |
| "What's the Threat Model?" | AWS Threat Composer style — AI analyzes code, generates STRIDE threats with mitigations |
| "Can it handle Java/Python/Go?" | Yes — auto-detects language, uses language-appropriate scanners and fix patterns |
| "What compliance frameworks?" | OWASP Top 10, PCI-DSS 6.5, SOC2 CC6.x, HIPAA §164.312, NIST SP 800-53 |

---

## 📂 Important Files Quick Reference

```
Start the bot:        python -m uvicorn app.main:app --reload
Run a scan:           python tests/test_scan_route.py
Generate report:      python tests/regen_report.py
Check SonarQube:      python tests/check_sonar_projects.py
Verify report:        python tests/check_report.py
View report:          http://localhost:8000/report/scan?scan_file=FILENAME
All reports list:     http://localhost:8000/reports
API docs:             http://localhost:8000/docs
```

---

*Generated by Security Orchestrator Bot v2.0 — Ready for interview demo* 🎯
