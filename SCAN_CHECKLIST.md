# 🛡️ Security Scan Checklist
### When you receive a new code repository to scan

---

## ✅ Pre-Flight (do once, stays ready)

- [ ] **Bot is running** → open terminal in `security-orch-bot/` and run:
  ```
  python -m uvicorn app.main:app --reload --port 8000
  ```
- [ ] **Verify bot is healthy** → open browser: `http://localhost:8000/health`
  - Should show: `github_configured: true`, `openai_configured: true`
- [ ] **SonarQube is running** → open browser: `http://localhost:9000`
  - Should show the SonarQube dashboard (login: admin/admin)

---

## 🚀 When Customer Gives You a Repo URL

### Step 1 — Get the repo details from the customer
```
Repo URL:    https://github.com/OWNER/REPO-NAME
Branch:      main  (or master)
```

### Step 2 — Run ONE command
Open a terminal in `security-orch-bot/` and run:
```bash
python tests/test_scan_route.py \
  --repo-url  https://github.com/OWNER/REPO-NAME \
  --repo-owner OWNER \
  --repo-name  REPO-NAME \
  --branch     main
```

**Example (AWSGoat):**
```bash
python tests/test_scan_route.py \
  --repo-url  https://github.com/madhugudla-collab/AWSGoat \
  --repo-owner madhugudla-collab \
  --repo-name  AWSGoat \
  --branch     master
```

### Step 3 — Watch it run (~2–5 minutes)
The terminal will print:
```
✅ Language detected:  python / java / javascript
✅ Scanners used:      sonarqube, semgrep, bandit
✅ Findings:           XX total
⏳ Polling for PRs...
```

### Step 4 — Get results
When done, you will see:
```
✅ Analysis complete!

📊 Severity Breakdown:
   🔴 CRITICAL:  X
   🟠 HIGH:      X
   🟡 MEDIUM:    X
   🟢 LOW:       X

🔀 GitHub PRs created (X):
   → https://github.com/OWNER/REPO/pull/1
   → https://github.com/OWNER/REPO/pull/2

📊 HTML SECURITY REPORT:
➜  http://localhost:8000/report/scan?scan_file=YYYYMMDD_scan_REPO_ID.json
```

### Step 5 — Open the HTML Report
1. Copy the URL printed above
2. Paste in Chrome/Edge browser
3. Report shows: Severity Dashboard + All Findings + GitHub PRs + Compliance + Threat Model

### Step 6 — Share the report
- **PDF:** Press `Ctrl+P` → Save as PDF → share via email/Slack
- **Live link:** Share `http://localhost:8000/report/scan?scan_file=...` (while bot is running)
- **GitHub PRs:** Share the PR links directly with the dev team

---

## 🔍 What the Bot Does Automatically

| What | How |
|------|-----|
| Clone the repo | Git clone to `data/cloned_repos/` |
| Detect language | Counts file extensions (`.py` → Python, `.java` → Java, etc.) |
| Run scanners | SonarQube + Semgrep + Bandit (Python) / Safety / npm-audit (JS) |
| Filter findings | CRITICAL + HIGH → GitHub PR with AI fix |
| Create PRs | One PR per vulnerability type (e.g., SQL Injection, XSS, Path Traversal) |
| Generate report | 80–100KB HTML with all findings, PRs, compliance, and threat model |

---

## ⚡ Quick Reference Commands

```bash
# Start bot
python -m uvicorn app.main:app --reload --port 8000

# Scan a repo (replace OWNER / REPO / BRANCH)
python tests/test_scan_route.py --repo-url https://github.com/OWNER/REPO --repo-owner OWNER --repo-name REPO --branch main

# Check scan status manually
# (thread_id printed when scan starts)
curl http://localhost:8000/scan/status/THREAD-ID

# List all past reports
curl http://localhost:8000/logs

# View API docs
http://localhost:8000/docs
```

---

## ❗ Troubleshooting

| Problem | Fix |
|---------|-----|
| Bot not running | Run: `python -m uvicorn app.main:app --reload` |
| 0 findings | SonarQube may be down → check `http://localhost:9000` |
| No PRs created | Check `GITHUB_TOKEN` in `.env` has write access to the repo |
| Scan times out | Repo may be large — try again with `--wait 600` |
| Language wrong | Add `--branch` flag to match the correct default branch |

---

*Security Orchestrator Bot v2.0 — scan any repo in under 5 minutes*
