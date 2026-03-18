# 🚀 Interview Quick Guide — Security Orchestrator Bot

> **Goal: Identify, analyze, and remediate vulnerabilities in ANY repo within 1 hour.**
> The bot is 100% generic — nothing is hardcoded to a specific pipeline, repo, or tool.

---

## ⚡ Key Architecture — "Is This Generic?"

**YES. Everything is parameterized.** The bot receives the pipeline URL, repo details, and tool locations as
request parameters — not hardcoded values. Tomorrow if your interviewer gives you a completely
different repo and Jenkins pipeline, you pass different parameters. Zero code changes.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Orchestrator Bot                     │
│                    http://localhost:8000                         │
│                                                                  │
│  POST /webhook/jenkins/pipeline  ←── ANY Jenkins build URL      │
│  POST /scan                      ←── ANY GitHub/GitLab repo URL  │
│  POST /onboard                   ←── ANY new repo to onboard     │
└─────────────────────────────────────────────────────────────────┘
```

The bot **does NOT care** which pipeline, which repo, or which team. It reads whatever console log
is at the URL you give it, finds findings from any of the 5 scan tools, and acts automatically.

---

## 🔄 Three Operating Modes (Jenkins is Optional!)

### Mode 1 — Jenkins Ran The Scans, Bot Acts On Results
```
Jenkins Pipeline (SonarQube + Snyk + Trivy + ZAP + Checkov)
         ↓
   POST /webhook/jenkins/pipeline   ← with build_url parameter
         ↓
   Bot reads Jenkins console log via Jenkins API
         ↓
   5 parsers run independently on the same log
         ↓
   SAST → GitHub PR | SCA → Issue | Container → Issue | IaC → PR
```
**When to use:** You already have a Jenkins pipeline running scans. You just point the bot at it.

### Mode 2 — No Jenkins, Bot Does Everything Itself
```
POST /scan  ←  just a GitHub repo URL, no Jenkins needed
      ↓
   Bot clones the repo
      ↓
   Auto-detects language (Python/Java/JS/Go/Ruby)
      ↓
   Runs appropriate scanners locally (Bandit, Semgrep, Safety, npm-audit)
      ↓
   AI analysis → GitHub PR created
```
**When to use:** No Jenkins available, or for a quick demo in under 2 minutes.

### Mode 3 — Bot Onboards a New Repo to Jenkins Automatically
```
POST /onboard  ←  repo owner + repo name + language
      ↓
   Bot generates a complete Jenkinsfile with the right scan stages
      ↓
   You add Jenkinsfile to repo → Jenkins runs pipeline
      ↓
   Jenkins auto-calls /webhook/jenkins/pipeline at end of each build
```
**When to use:** Interviewer gives you a brand new repo with no CI/CD. You set it up from scratch.

---

## 🔁 How Automation Works — "Is the Pipeline Link Hardcoded?"

**NO. The pipeline link is a parameter, not hardcoded.** Here's what the bot receives:

```json
POST /webhook/jenkins/pipeline
{
  "build_url":              "http://ANY-JENKINS-HOST/job/ANY-JOB/ANY-BUILD-NUMBER/",
  "job_name":               "any job name",
  "repo_owner":             "any GitHub org or user",
  "repo_name":              "any GitHub repo",
  "branch":                 "main",
  "sonarqube_project_key":  "any SonarQube project key",
  "sonarqube_url":          "http://any-sonarqube-server:9001",
  "jenkins_user":           "any Jenkins username",
  "jenkins_workspace":      "path/to/workspace/on/jenkins/machine"
}
```

Every field is a parameter. The same bot code works for:
- `http://localhost:8080/job/DevSecOpsEndtoEnd/18/` (your current setup)
- `http://jenkins.company.com/job/BankingApp/45/` (interviewer's setup)
- `http://ci.startup.io/job/frontend-security/3/` (any other setup)

---

## ⚙️ How Jenkins Automatically Triggers The Bot

In a Jenkins pipeline, the `post { always { ... } }` section runs **after every build**.
The bot is called automatically — no human clicks needed:

```groovy
// In any Jenkinsfile - add this to trigger the bot automatically
post {
    always {
        bat """
        curl -X POST "http://localhost:8000/webhook/jenkins/pipeline" ^
          -H "Content-Type: application/json" ^
          -d "{\\"build_url\\": \\"%BUILD_URL%\\", ^
               \\"job_name\\": \\"%JOB_NAME%\\", ^
               \\"repo_owner\\": \\"YOUR_GITHUB_ORG\\", ^
               \\"repo_name\\": \\"YOUR_REPO_NAME\\", ^
               \\"jenkins_user\\": \\"admin\\"}"
        """
    }
}
```

With this in place:
1. Engineer pushes code → Jenkins runs all security scans
2. Jenkins posts to the bot automatically (no human action)
3. Bot parses results → creates GitHub Issues/PRs automatically
4. Security team reviews PRs and Issues in GitHub

---

## 🎯 Scenario 1 — Interviewer's Existing Jenkins Pipeline

### Step 1: Check the bot is healthy
```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","github_configured":true,"openai_configured":true}
```

### Step 2: Point the bot at the interviewer's pipeline build
```bash
curl -X POST http://localhost:8000/webhook/jenkins/pipeline \
  -H "Content-Type: application/json" \
  -d '{
    "build_url":    "http://JENKINS-HOST/job/JOB-NAME/BUILD-NUMBER/",
    "job_name":     "JOB-NAME",
    "repo_owner":   "GITHUB-ORG",
    "repo_name":    "REPO-NAME",
    "branch":       "main",
    "jenkins_user": "admin",
    "sonarqube_url": "http://SONARQUBE-HOST:9001",
    "sonarqube_project_key": "PROJECT-KEY"
  }'
```

### Step 3: Wait ~90 seconds, check results
```bash
# See all generated reports
curl http://localhost:8000/logs

# See GitHub — Issues and PRs were auto-created
# https://github.com/GITHUB-ORG/REPO-NAME/issues
# https://github.com/GITHUB-ORG/REPO-NAME/pulls
```

### What the bot does automatically:

| Scan Found In Log | Tool | Findings → Action |
|-------------------|------|-------------------|
| `[INFO] ✗ ... [High Severity]` | Snyk (SCA) | 📌 GitHub Issue with all CVEs grouped by severity |
| `✗ Medium severity vulnerability found in ...` | Trivy (Container) | 📌 GitHub Issue with OS CVEs |
| `Check: CKV... FAILED for resource:` | Checkov (IaC) | 📌 GitHub Issue (or 🔀 PR with AI Terraform fix) |
| SonarQube REST API | SonarQube (SAST) | 🔀 GitHub PR with AI code fix |
| `Output.html` in workspace | OWASP ZAP (DAST) | 📄 JSON report saved + 📌 Issue for HIGH findings |

---

## 🎯 Scenario 2 — Brand New Repo, No Jenkins

### Option A: Direct Scan (fastest — under 2 minutes)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url":    "https://github.com/OWNER/REPO",
    "repo_owner":  "OWNER",
    "repo_name":   "REPO",
    "branch":      "main",
    "create_pr":   true
  }'
# Bot clones → scans → creates GitHub PR automatically
```

### Option B: Onboard to Jenkins (~5 minutes)
```bash
# Step 1: Generate Jenkinsfile
curl -X POST http://localhost:8000/onboard \
  -d '{"repo_owner": "OWNER", "repo_name": "REPO", "language": "java"}'

# Step 2: Copy the Jenkinsfile from the response to the repo
# Step 3: In Jenkins: New Item → Pipeline → SCM → Git → add repo URL → Build Now
# Step 4: Jenkins runs, calls bot automatically at the end
```

---

## 🔍 How The Bot Parses 5 Different Scan Types

The bot fetches the Jenkins console log (plain text, ~300K chars) and runs 5 independent parsers:

```
Jenkins Console Log (raw text from /consoleText API)
    │
    ├─ Parser 1 (SAST):      Calls SonarQube REST API → gets issues
    │                         → Creates GitHub PR with AI-generated code fix
    │
    ├─ Parser 2 (SCA):       Scans lines for "[INFO] ✗ ... [High Severity][URL]"
    │                         → Reads next line for "introduced by pkg@version"
    │                         → Creates GitHub Issue grouped by severity
    │
    ├─ Parser 3 (Container): Scans lines for "severity vulnerability found in pkg"
    │                         → Reads next line for "Description: CVE-XXXX-YYYY"
    │                         → Creates GitHub Issue with CVE list
    │
    ├─ Parser 4 (DAST):      Reads Output.html from Jenkins workspace
    │                         → Parses ZAP HTML report with BeautifulSoup
    │                         → Saves JSON report + GitHub Issue for HIGH findings
    │
    └─ Parser 5 (IaC):       Scans lines for 'Check: CKV... FAILED for resource:'
                              → Groups by Terraform resource type
                              → Creates GitHub PR with AI Terraform fix (or Issue)
```

**Key design principle:** Each parser is **independent** — if one fails (e.g., SonarQube is down),
the other 4 continue. The bot never stops mid-workflow because one tool had issues.

---

## 🛠️ All Available Endpoints

| Endpoint | What It Does | Jenkins Needed? |
|----------|-------------|-----------------|
| `GET /health` | Check bot status & configured tokens | No |
| `POST /webhook/jenkins/pipeline` | **Full DevSecOps** — reads ANY Jenkins build log | Yes (build must exist) |
| `POST /webhook/jenkins` | Simple webhook — sends pre-parsed findings | Yes |
| `POST /scan` | Clones & scans ANY repo directly | **No** |
| `POST /onboard` | Generates Jenkinsfile for ANY new repo | No |
| `GET /logs` | List all saved security reports | No |
| `GET /logs/{filename}` | View a specific report JSON | No |
| `GET /docs` | Swagger UI — test all endpoints interactively | No |

---

## 🔧 Enable SAST GitHub PR Creation

SAST is **skipped** if `SONARQUBE_TOKEN` is not configured. To enable:

1. Open SonarQube: `http://localhost:9001` (or wherever it's running)
2. **My Account → Security → Generate Tokens**
3. Copy the `squ_...` token
4. Add to `security-orch-bot/.env`:
   ```
   SONARQUBE_TOKEN=squ_your-token-here
   ```
5. Restart: `.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000`

---

## 🧪 Run The Full End-to-End Test

```bash
python security-orch-bot/tests/test_pipeline.py
```

What the test does:
1. Calls `POST /webhook/jenkins/pipeline` with the DevSecOpsEndtoEnd build #18
2. Waits 90 seconds for AI analysis + GitHub API calls
3. Prints a summary of all findings and GitHub links created

Expected output:
```
==================================================
  DEVSECOPS PIPELINE RESULTS
==================================================
  SAST (SonarQube) : skipped   (set SONARQUBE_TOKEN to enable)
  SCA  (Snyk)      : ok        55 findings
  Container(Trivy) : ok        30 CVEs
  DAST (ZAP)       : ok         0 alerts (ZAP scanned example.com)
  IaC  (Checkov)   : ok        16 findings

  PRs created    : 0
  Alerts created : 3
    [SCA]       https://github.com/.../issues/3
    [Container] https://github.com/.../issues/4
    [IaC]       https://github.com/.../issues/5
==================================================
```

---

## 💡 Interview Talking Points

### "How does it work?"
> "The bot has a single API endpoint that accepts any Jenkins build URL as a parameter.
> It calls the Jenkins REST API to fetch the console log — that's just plain text.
> It then runs 5 independent parsers on that text: one for SonarQube (via API), one for Snyk,
> one for Trivy, one for ZAP, and one for Checkov. Each scanner type gets a different action:
> source code issues become GitHub PRs, OS-level CVEs become GitHub Issues, and IaC
> misconfigurations become either a PR with the Terraform fix or an Issue.
> All handlers run independently — one failure never stops the others."

### "Is it hardcoded to your specific pipeline?"
> "Not at all. The pipeline URL, repo owner, repo name, SonarQube URL — they're all request
> parameters. You can point it at any Jenkins instance by changing what you POST to the endpoint.
> For the demo I used my DevSecOpsEndtoEnd pipeline, but the code would work identically with
> any other pipeline that runs these tools."

### "Does it need Jenkins?"
> "No, Jenkins is optional. The `/scan` endpoint can clone any GitHub repo, detect the language,
> run scanners locally, and create a GitHub PR — all without Jenkins. Jenkins adds value because
> it gives you enterprise-grade tools like SonarQube, Snyk, and ZAP that are hard to run locally.
> But for a quick scan during the interview, I can bypass Jenkins entirely."

### "How is the bot triggered automatically?"
> "Jenkins has a `post { always { } }` section that runs after every build regardless of success
> or failure. You put a curl command there that posts to the bot with the build URL. From that
> point on, every code push → Jenkins scan → bot analyzes → GitHub Issue/PR. No human needs
> to manually trigger anything. The whole pipeline is event-driven."

### "Why different actions for different scan types?"
> "Because the fix strategy is different. SAST finds bugs in source code — the AI can read the
> code and write a specific fix, so we create a PR. SCA finds vulnerable library versions — we
> can suggest upgrading pom.xml, but the developer needs to verify compatibility, so we create
> a PR description with the dependency changes. Container CVEs are in the OS layer — you can't
> fix them by changing app code, the ops team needs to update the base image, so we create an
> Issue for them. IaC misconfigurations are in Terraform files that the AI can rewrite directly,
> so we create a PR. DAST is a runtime test of a live app — the findings need human analysis of
> the application behavior, so we save a structured report and create Issues."

### "What's the compliance angle?"
> "The AI prompt explicitly mentions SOC2, HIPAA, and PCI-DSS. So every GitHub PR includes
> the compliance mapping — for example, a Checkov finding for wildcard IAM permissions maps to
> SOC2 CC6.3 (least privilege) and PCI-DSS Requirement 7.1. This turns a raw security scan
> into an audit-ready finding with remediation guidance."

---

## 🚦 1-Hour Interview Checklist

- [ ] `GET /health` → `github_configured: true`, `openai_configured: true`
- [ ] Have interviewer's repo URL and Jenkins build URL ready
- [ ] `POST /webhook/jenkins/pipeline` → starts in background → wait 90s
- [ ] Show GitHub Issues and PRs auto-created
- [ ] Explain the 5 scan types and why each gets a different action
- [ ] Show `GET /logs` → explain the saved report structure
- [ ] If no Jenkins: use `POST /scan` with the repo URL → instant demo
- [ ] If new repo: use `POST /onboard` → shows generated Jenkinsfile
