"""
DevSecOps Pipeline Handler
============================
Processes results from a full Jenkins DevSecOps pipeline and acts differently
per scan type:

  SAST (SonarQube)    → Fetch issues via API → Create one PR per vulnerability TYPE (parallel, fast)
  SCA (Snyk/OWASP)    → Parse console log → Create PR to bump dependency version
  Container (Trivy)   → Parse console log → Create GitHub Issue alert
  DAST (ZAP)          → Read ZAP Output.html → Generate & save security report
  IaC (Checkov)       → Parse console log → Create GitHub PR to fix Terraform

Speed improvements:
  - All GitHub API calls use parallel ThreadPoolExecutor
  - Direct OpenAI API instead of LangGraph orchestrator (10x faster)
  - MAX_SAST_PRS=8 cap to avoid processing all unique rules
"""

import os
import re
import json
import base64
import requests
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

GITHUB_API = "https://api.github.com"
MAX_SAST_PRS = 8          # max unique vulnerability types to create PRs for
MAX_FILES_PER_RULE = 3    # max files to fix per rule (avoid very slow runs)


# ─────────────────────────────────────────────────────────────
# Fast AI Helper — direct OpenAI (no LangGraph overhead)
# ─────────────────────────────────────────────────────────────

def _openai_analyze(prompt: str, max_tokens: int = 1500) -> str:
    """Call OpenAI directly — much faster than LangGraph orchestrator."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[AI] OpenAI call failed: {e}")
        return ""


# ─────────────────────────────────────────────────────────────
# Jenkins Console Fetch
# ─────────────────────────────────────────────────────────────

def fetch_jenkins_console(build_url: str, user: str = "admin", token: str = None) -> str:
    """Fetch the full console log for a Jenkins build."""
    build_url = build_url.rstrip("/")
    console_url = f"{build_url}/consoleText"
    auth = (user, token) if token else (user, user)
    try:
        resp = requests.get(console_url, auth=auth, timeout=20)
        if resp.status_code == 200:
            print(f"[Console] Fetched {len(resp.text)} chars from {console_url}")
            return resp.text
        print(f"[Console] HTTP {resp.status_code} for {console_url}")
    except Exception as e:
        print(f"[Console] Could not fetch Jenkins console: {e}")
    return ""


# ─────────────────────────────────────────────────────────────
# GitHub Helpers
# ─────────────────────────────────────────────────────────────

def _gh_headers(token: str = None) -> Dict:
    t = token or os.getenv("GITHUB_TOKEN", "")
    return {"Authorization": f"token {t}", "Accept": "application/vnd.github.v3+json"}


def _get_github_headers():
    return _gh_headers()


def _gh_get_branch_sha(owner: str, repo: str, branch: str, token: str) -> Optional[str]:
    try:
        r = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/heads/{branch}",
            headers=_gh_headers(token), timeout=10,
        )
        if r.status_code == 200:
            return r.json()["object"]["sha"]
    except Exception as e:
        print(f"[GH] get_sha failed: {e}")
    return None


def _gh_create_branch(owner: str, repo: str, branch_name: str, base_branch: str, token: str) -> bool:
    sha = _gh_get_branch_sha(owner, repo, base_branch, token)
    if not sha:
        return False
    try:
        r = requests.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs",
            headers=_gh_headers(token),
            json={"ref": f"refs/heads/{branch_name}", "sha": sha},
            timeout=10,
        )
        if r.status_code in (200, 201):
            print(f"[GH] ✅ Branch: {branch_name}")
            return True
        if r.status_code == 422:
            print(f"[GH] Branch exists: {branch_name}")
            return True
        print(f"[GH] Branch failed: {r.status_code}")
    except Exception as e:
        print(f"[GH] create_branch: {e}")
    return False


def _gh_fetch_file(owner: str, repo: str, file_path: str, ref: str, token: str):
    """Returns (content_str, sha) or (None, None)."""
    try:
        r = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}",
            headers=_gh_headers(token), params={"ref": ref}, timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            return base64.b64decode(d["content"]).decode("utf-8", errors="replace"), d["sha"]
        print(f"[GH] fetch {file_path} → {r.status_code}")
    except Exception as e:
        print(f"[GH] fetch_file: {e}")
    return None, None


def _gh_push_file(owner: str, repo: str, branch: str, file_path: str,
                  content: str, existing_sha: Optional[str], commit_msg: str, token: str) -> bool:
    try:
        payload = {
            "message": commit_msg,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if existing_sha:
            payload["sha"] = existing_sha
        r = requests.put(
            f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}",
            headers=_gh_headers(token), json=payload, timeout=20,
        )
        if r.status_code in (200, 201):
            return True
        print(f"[GH] push {file_path} → {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"[GH] push_file: {e}")
    return False


# ─────────────────────────────────────────────────────────────
# SAST — SonarQube Rule Mapping
# ─────────────────────────────────────────────────────────────

_RULE_SLUG = {
    "java:S2245": "predictable-random",
    "java:S1948": "mutable-servlet-field",
    "java:S2184": "division-by-zero",
    "java:S3457": "unhandled-exceptions",
    "java:S2077": "sql-injection",
    "java:S5131": "xss-reflected",
    "java:S4507": "debug-features",
    "java:S2068": "hardcoded-credentials",
    "java:S5144": "ssrf",
    "java:S6096": "path-traversal",
    "java:S5808": "missing-authorization",
    "java:S5332": "insecure-protocol",
    "java:S6350": "ldap-injection",
    "java:S2278": "weak-cryptography",
    "java:S2053": "weak-password-hash",
    "java:S1989": "exception-in-servlet",
    "java:S5852": "regex-dos",
    "java:S3329": "weak-cipher",
    "java:S4426": "weak-key-size",
    "java:S4790": "weak-hash",
    "java:S2755": "xxe-injection",
    "java:S2083": "path-traversal-injection",
    "java:S1943": "unsafe-xml",
}

_RULE_DISPLAY = {
    "java:S2245": "Predictable Random Number Generation",
    "java:S1948": "Mutable Servlet Instance Field (Thread Safety)",
    "java:S2184": "Division by Zero Risk",
    "java:S3457": "Unhandled Exceptions",
    "java:S2077": "SQL Injection Risk",
    "java:S5131": "Cross-Site Scripting (XSS)",
    "java:S4507": "Debug Features Enabled in Production",
    "java:S2068": "Hardcoded Credentials",
    "java:S5144": "Server-Side Request Forgery (SSRF)",
    "java:S6096": "Path Traversal",
    "java:S5808": "Missing Authorization",
    "java:S5332": "Insecure Protocol (HTTP instead of HTTPS)",
    "java:S6350": "LDAP Injection",
    "java:S2278": "Weak Cryptography Algorithm",
    "java:S2053": "Weak Password Hashing",
    "java:S1989": "Exception Thrown in Servlet",
    "java:S5852": "Regex Denial of Service",
    "java:S3329": "Weak Cipher Block Chaining",
    "java:S4426": "Weak Cryptographic Key Size",
    "java:S4790": "Weak Hashing Algorithm",
    "java:S2755": "XML External Entity (XXE) Injection",
    "java:S2083": "Path Traversal Injection",
    "java:S1943": "Unsafe XML Processing",
}

_RULE_COMPLIANCE = {
    "java:S2245": "OWASP A02 (Crypto Failures), PCI-DSS 6.5.3, SOC2 CC6.1",
    "java:S1948": "SOC2 CC6.6, HIPAA §164.312(b)",
    "java:S2184": "SOC2 CC7.2, HIPAA §164.312(b)",
    "java:S3457": "SOC2 CC7.2, PCI-DSS 6.5.5",
    "java:S2077": "OWASP A03, PCI-DSS 6.5.1, SOC2 CC6.1",
    "java:S5131": "OWASP A03, PCI-DSS 6.5.7, HIPAA §164.312(c)(1)",
    "java:S2068": "OWASP A07, PCI-DSS 6.3.1, SOC2 CC6.3",
    "java:S6096": "OWASP A01, PCI-DSS 6.5.8, SOC2 CC6.6",
    "java:S2755": "OWASP A05, PCI-DSS 6.5.1, SOC2 CC6.1",
    "java:S4790": "OWASP A02, PCI-DSS 6.5.3, HIPAA §164.312(a)(2)(iv)",
    "java:S5332": "OWASP A02, PCI-DSS 4.1, HIPAA §164.312(e)(1)",
}


def _rule_slug(rule: str) -> str:
    if rule in _RULE_SLUG:
        return _RULE_SLUG[rule]
    return re.sub(r"[^a-z0-9]+", "-", rule.lower()).strip("-")


def _rule_display(rule: str, fallback_msg: str = "") -> str:
    if rule in _RULE_DISPLAY:
        return _RULE_DISPLAY[rule]
    if fallback_msg:
        clean = re.sub(r"\s*\(.*", "", fallback_msg).strip()[:60]
        if len(clean) > 6:
            return clean
    return f"Security Issue ({rule})"


def _rule_compliance(rule: str) -> str:
    return _RULE_COMPLIANCE.get(rule, f"OWASP Top 10, PCI-DSS 6.5.x, SOC2 CC6.1")


# ─────────────────────────────────────────────────────────────
# SAST — AI Code Fix (fast, direct OpenAI)
# ─────────────────────────────────────────────────────────────

# Language-specific fix guidance for the AI
_LANG_FIX_GUIDE = {
    "java": (
        "- java.util.Random → java.security.SecureRandom\n"
        "- Add null/zero checks before division operations\n"
        "- Make mutable servlet instance fields final or move to method scope\n"
        "- Wrap sendRedirect in try-catch IOException\n"
        "- Use PreparedStatement for SQL (not string concatenation)\n"
        "- Encode output for XSS: ESAPI.encoder().encodeForHTML()\n"
        "- Use SecretKeySpec with AES/GCM instead of weak ciphers\n"
    ),
    "python": (
        "- Use secrets module instead of random for security tokens\n"
        "- Use parameterized queries (cursor.execute(query, params)) not f-strings for SQL\n"
        "- Validate and sanitize all user inputs with bleach or html.escape()\n"
        "- Use subprocess with shell=False and list arguments, not shell=True\n"
        "- Use hashlib.pbkdf2_hmac or bcrypt for password hashing, not md5/sha1\n"
        "- Use os.path.realpath() and check prefix for path traversal\n"
        "- Use ssl.create_default_context() for TLS connections\n"
        "- Avoid pickle.loads() on untrusted data; use json instead\n"
    ),
    "javascript": (
        "- Use crypto.randomBytes() instead of Math.random() for security tokens\n"
        "- Use parameterized queries for SQL (never template literals)\n"
        "- Sanitize HTML output with DOMPurify or he.encode()\n"
        "- Add helmet middleware for HTTP security headers\n"
        "- Use bcrypt for password hashing, not md5/sha1\n"
        "- Validate all req.params / req.body with Joi or express-validator\n"
        "- Use path.resolve() and check prefix for path traversal\n"
        "- Set httpOnly and secure flags on cookies\n"
    ),
    "typescript": (
        "- Use crypto.randomBytes() instead of Math.random() for security tokens\n"
        "- Use parameterized queries for SQL (never template literals)\n"
        "- Sanitize HTML output with DOMPurify or he.encode()\n"
        "- Add helmet middleware for HTTP security headers\n"
        "- Use bcrypt for password hashing, not md5/sha1\n"
        "- Validate all req.params / req.body with Joi or class-validator\n"
        "- Set httpOnly and secure flags on cookies\n"
    ),
    "go": (
        "- Use crypto/rand instead of math/rand for security tokens\n"
        "- Use db.QueryRow with ? placeholders for SQL, not fmt.Sprintf\n"
        "- Use html/template (not text/template) to auto-escape HTML output\n"
        "- Use golang.org/x/crypto/bcrypt for password hashing\n"
        "- Use filepath.Clean() and strings.HasPrefix() for path traversal checks\n"
        "- Use crypto/tls with minimum TLS 1.2 for connections\n"
        "- Use os/exec with explicit argument lists, not shell strings\n"
    ),
    "ruby": (
        "- Use SecureRandom instead of Random for tokens\n"
        "- Use ActiveRecord parameterized queries, not string interpolation\n"
        "- Use html_escape or ERB::Util.html_escape for XSS prevention\n"
        "- Use bcrypt gem for password hashing\n"
        "- Use File.expand_path and check prefix for path traversal\n"
        "- Use Open3.capture3 with array args instead of backticks for shell\n"
    ),
    "php": (
        "- Use random_bytes() or openssl_random_pseudo_bytes() for tokens\n"
        "- Use PDO with prepared statements for SQL queries\n"
        "- Use htmlspecialchars() with ENT_QUOTES for XSS prevention\n"
        "- Use password_hash(PASSWORD_BCRYPT) for password hashing\n"
        "- Use realpath() and check prefix for path traversal\n"
        "- Disable error display in production (display_errors=Off)\n"
    ),
    "csharp": (
        "- Use RNGCryptoServiceProvider instead of System.Random for tokens\n"
        "- Use SqlCommand with SqlParameter for SQL queries\n"
        "- Use HttpUtility.HtmlEncode() for XSS prevention\n"
        "- Use BCrypt.Net or PBKDF2 for password hashing\n"
        "- Use Path.GetFullPath() and check prefix for path traversal\n"
        "- Use SecureString for sensitive data in memory\n"
    ),
}


def _detect_lang_from_file(file_path: str) -> str:
    """Detect language from file extension."""
    ext_map = {
        ".java": "java", ".py": "python", ".js": "javascript",
        ".ts": "typescript", ".go": "go", ".rb": "ruby",
        ".php": "php", ".cs": "csharp", ".cpp": "cpp", ".c": "c",
    }
    ext = os.path.splitext(file_path)[-1].lower()
    return ext_map.get(ext, "")


def _ai_fix_source_code(source_code: str, file_path: str, findings: List[Dict],
                         language: str = "") -> Optional[str]:
    """
    Generate AI-fixed source code. Language-agnostic — works for Java, Python,
    JavaScript, TypeScript, Go, Ruby, PHP, C# and any other language.
    Returns fixed code string or None.
    """
    # Auto-detect language from file extension if not provided
    lang = language or _detect_lang_from_file(file_path) or "the language used in this file"

    vuln_lines = "\n".join(
        f"  - Line {f.get('line','?')}: {f.get('message', f.get('vulnerability',''))}"
        for f in findings
    )

    # Get language-specific guidance (or a generic set)
    lang_key = lang.lower().replace("#", "sharp")
    lang_guide = _LANG_FIX_GUIDE.get(lang_key, (
        "- Use secure random number generation (not Math.random / rand / random)\n"
        "- Use parameterized queries for SQL, never string concatenation\n"
        "- Sanitize/encode output to prevent XSS\n"
        "- Use strong password hashing (bcrypt/argon2/PBKDF2)\n"
        "- Validate and sanitize all user inputs\n"
        "- Use secure TLS connections (not outdated SSL)\n"
    ))

    prompt = (
        f"You are a senior security engineer. Fix these security vulnerabilities in the {lang} source file below.\n\n"
        f"FILE: {file_path}\n\n"
        f"VULNERABILITIES TO FIX:\n{vuln_lines}\n\n"
        f"CURRENT SOURCE CODE:\n{source_code}\n\n"
        f"RULES:\n"
        f"1. Return ONLY the complete fixed source code — NO markdown, NO code fences, NO explanations.\n"
        f"2. Fix ONLY the listed vulnerabilities — keep all business logic intact.\n"
        f"3. On each changed line add a comment: // SECURITY FIX: <brief reason>  "
        f"(or # SECURITY FIX: for Python/Ruby)\n"
        f"4. Apply {lang} security best practices:\n"
        f"{lang_guide}"
    )

    fixed = _openai_analyze(prompt, max_tokens=4000)
    if not fixed:
        return None

    # Strip markdown fences if AI added them anyway
    if "```" in fixed:
        m = re.search(r"```(?:\w+)?\n(.*?)\n?```", fixed, re.DOTALL)
        if m:
            fixed = m.group(1)

    # Sanity check: result must contain code-like keywords
    code_keywords = [
        # Java/C#/Go/TS/JS
        "class ", "import ", "public ", "private ", "function ", "def ",
        "package ", "func ", "const ", "let ", "var ", "module",
        # Python/Ruby/PHP
        "def ", "class ", "import ", "require", "<?php",
    ]
    if any(kw in fixed for kw in code_keywords):
        return fixed

    print(f"[SAST-FIX] AI response doesn't look like {lang} code for {file_path}")
    return None


# ─────────────────────────────────────────────────────────────
# SAST — Process ONE Rule Group → Branch + AI Fix + PR
# ─────────────────────────────────────────────────────────────

def _process_sast_rule(rule: str, rule_findings: List[Dict], data, timestamp: str, token: str) -> Optional[Dict]:
    """
    Process a single SonarQube rule:
    1. Create branch
    2. Fetch + AI-fix each affected file (parallel)
    3. Push fixed files
    4. Create PR
    Returns dict with pr_url, or None on failure.
    """
    from app.github_integration import create_github_pr

    slug = _rule_slug(rule)
    display = _rule_display(rule, rule_findings[0].get("message", ""))
    ts_short = timestamp[:13].replace("_", "-")
    branch_name = f"fix/security/{slug}-{ts_short}"

    print(f"\n[SAST] ▶ {display} ({len(rule_findings)} findings) → {branch_name}")

    # 1. Create branch
    if not _gh_create_branch(data.repo_owner, data.repo_name, branch_name, data.branch, token):
        print(f"[SAST] ✗ Could not create branch for {rule}")
        return None

    # 2. Group findings by file
    file_groups: Dict[str, List] = defaultdict(list)
    for f in rule_findings:
        fp = f.get("file", "")
        if fp:
            file_groups[fp].append(f)

    files_fixed = 0
    file_fix_details = []

    # 3. Fetch + fix files (parallel across files for this rule)
    def fix_one_file(file_path: str, file_findings: List[Dict]) -> tuple:
        src, sha = _gh_fetch_file(data.repo_owner, data.repo_name, file_path, data.branch, token)
        if not src:
            return file_path, None, None, sha
        fixed = _ai_fix_source_code(src, file_path, file_findings)
        if not fixed or fixed.strip() == src.strip():
            return file_path, None, None, sha
        return file_path, fixed, file_findings, sha

    file_items = list(file_groups.items())[:MAX_FILES_PER_RULE]

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fix_one_file, fp, ff): fp for fp, ff in file_items}
        for fut in as_completed(futures):
            file_path, fixed_code, ff, original_sha = fut.result()
            if not fixed_code:
                continue
            # Get sha on new branch (might be same as base if branch was just created)
            _, branch_sha = _gh_fetch_file(data.repo_owner, data.repo_name, file_path, branch_name, token)
            ok = _gh_push_file(
                owner=data.repo_owner, repo=data.repo_name, branch=branch_name,
                file_path=file_path, content=fixed_code,
                existing_sha=branch_sha or original_sha,
                commit_msg=f"[Security Bot] {display}: fix {file_path.split('/')[-1]}",
                token=token,
            )
            if ok:
                files_fixed += 1
                lines = [str(f.get("line", "?")) for f in ff]
                file_fix_details.append(f"`{file_path}` (lines {', '.join(lines)})")
                print(f"[SAST] ✅ Fixed: {file_path}")

    # 4. If no code fixes, push an analysis markdown so branch has a commit
    if files_fixed == 0:
        md = (
            f"# Security Analysis: {display}\n\n"
            f"**Rule:** `{rule}` | **Severity:** {rule_findings[0].get('severity','HIGH')}\n"
            f"**Build:** {data.build_url} | **Findings:** {len(rule_findings)}\n\n"
            f"## Affected Locations\n\n"
            + "\n".join(f"- `{f.get('file','')}` line **{f.get('line','?')}**: {f.get('message','')}" for f in rule_findings)
            + f"\n\n## Fix Recommendation\n\n{_get_fix_guidance(rule)}\n"
        )
        _gh_push_file(
            owner=data.repo_owner, repo=data.repo_name, branch=branch_name,
            file_path=f"security-reports/sast-{slug}-{ts_short}.md",
            content=md, existing_sha=None,
            commit_msg=f"[Security Bot] Security analysis: {display}",
            token=token,
        )

    # 5. Build PR body
    pr_body = f"## 🔐 [SECURITY-FIX] {display}\n\n"
    pr_body += f"| Field | Value |\n|-------|-------|\n"
    pr_body += f"| **Rule** | `{rule}` |\n"
    pr_body += f"| **Severity** | {rule_findings[0].get('severity','HIGH')} |\n"
    pr_body += f"| **Findings** | {len(rule_findings)} |\n"
    pr_body += f"| **Files Fixed** | {files_fixed} |\n"
    pr_body += f"| **Build** | [{data.build_url}]({data.build_url}) |\n\n"
    pr_body += "---\n\n### 📍 Affected Files & Lines\n\n"
    for f in rule_findings:
        pr_body += f"- `{f.get('file','?')}` **line {f.get('line','?')}**: {f.get('message', f.get('vulnerability',''))}\n"
    pr_body += "\n### 🔧 Fix Applied\n\n"
    if file_fix_details:
        pr_body += "Security Bot applied automated code fixes to:\n"
        for d in file_fix_details:
            pr_body += f"- {d}\n"
    else:
        pr_body += (
            f"> ℹ️ Could not read source from GitHub — manual fix required.\n\n"
            f"**Recommended fix:** {_get_fix_guidance(rule)}\n"
        )
    pr_body += f"\n### 📜 Compliance Impact\n\n`{rule}` → {_rule_compliance(rule)}\n"
    pr_body += "\n---\n*Security Orchestrator Bot — Do NOT auto-merge without review.*\n"

    # 6. Create PR
    try:
        pr_url = create_github_pr(
            repo_owner=data.repo_owner, repo_name=data.repo_name,
            branch_name=branch_name,
            title=f"[SECURITY-FIX] Fix for {display}",
            body=pr_body,
            base_branch=data.branch,
        )
        if pr_url:
            print(f"[SAST] ✅ PR: {pr_url}")
            return {"rule": rule, "display": display, "pr_url": pr_url,
                    "files_fixed": files_fixed, "count": len(rule_findings)}
    except Exception as e:
        print(f"[SAST] PR failed for {rule}: {e}")
    return None


def _get_fix_guidance(rule: str) -> str:
    """Return short fix guidance for a rule."""
    fixes = {
        "java:S2245": "Replace `new java.util.Random()` with `new java.security.SecureRandom()`",
        "java:S1948": "Make the field `static final`, move it to method scope, or add `volatile`/`synchronized`",
        "java:S2184": "Add a null/zero check before division: `if (divisor != 0) { ... }`",
        "java:S3457": "Wrap `response.sendRedirect()` in `try { } catch (IOException e) { }`",
        "java:S2077": "Use `PreparedStatement` with `?` parameters instead of string concatenation",
        "java:S5131": "Encode output with `ESAPI.encoder().encodeForHTML(input)` or `StringEscapeUtils.escapeHtml4()`",
        "java:S2068": "Move credentials to environment variables or a secrets manager",
        "java:S6096": "Validate and normalize the path, check it starts with the expected base directory",
        "java:S2755": "Disable external entity processing: `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`",
        "java:S4790": "Replace MD5/SHA-1 with SHA-256 or bcrypt for passwords",
        "java:S5332": "Change HTTP URLs to HTTPS",
    }
    return fixes.get(rule, "Review the SonarQube rule documentation and apply the recommended fix.")


# ─────────────────────────────────────────────────────────────
# SAST — Main Entry Point
# ─────────────────────────────────────────────────────────────

def handle_sast(data, report: dict, timestamp: str) -> List[Dict]:
    """
    1. Fetch all SonarQube findings
    2. Group HIGH/CRITICAL by rule (vulnerability type)
    3. Create one PR per rule (parallel) — max MAX_SAST_PRS
    4. Create one consolidated GitHub Issue listing all PRs
    """
    sonar_url = getattr(data, "sonarqube_url", "http://localhost:9000")
    project_key = getattr(data, "sonarqube_project_key", None) or data.repo_name
    sonar_token = os.getenv("SONARQUBE_TOKEN", "")
    token = os.getenv("GITHUB_TOKEN", "")

    print(f"[SAST] Querying SonarQube: {sonar_url} project={project_key}")

    if not sonar_token:
        report["sast"].update({"status": "skipped", "reason": "SONARQUBE_TOKEN not set"})
        return []

    try:
        resp = requests.get(
            f"{sonar_url}/api/issues/search",
            params={"componentKeys": project_key, "types": "VULNERABILITY,BUG",
                    "severities": "CRITICAL,MAJOR,MINOR", "ps": 50},
            auth=(sonar_token, ""), timeout=15,
        )
        if resp.status_code == 401:
            report["sast"].update({"status": "error", "reason": "Token expired"})
            return []
        if resp.status_code != 200:
            report["sast"].update({"status": "error", "reason": f"HTTP {resp.status_code}"})
            return []

        issues = resp.json().get("issues", [])
        sev_map = {"CRITICAL": "CRITICAL", "BLOCKER": "CRITICAL",
                   "MAJOR": "HIGH", "MINOR": "MEDIUM", "INFO": "LOW"}

        findings = [
            {
                "tool": "sonarqube",
                "rule": i.get("rule", ""),
                "message": i.get("message", "Unknown"),
                "vulnerability": f"{i.get('message','Unknown')} ({i.get('rule','')})",
                "file": i.get("component", "").split(":", 1)[-1],
                "line": i.get("line"),
                "severity": sev_map.get(i.get("severity", "MAJOR"), "HIGH"),
                "code": "",
            }
            for i in issues
        ]

        report["sast"]["findings_count"] = len(findings)
        report["sast"]["status"] = "ok"
        print(f"[SAST] {len(findings)} finding(s) found")

        if not findings or not token:
            if not token:
                print("[SAST] GITHUB_TOKEN not set — skipping PR creation")
            return findings

        # Group HIGH/CRITICAL by rule
        rule_groups: Dict[str, List] = defaultdict(list)
        for f in findings:
            if f["severity"] in ("CRITICAL", "HIGH"):
                rule_groups[f.get("rule", "unknown")].append(f)

        # Sort by count desc, cap at MAX_SAST_PRS
        sorted_rules = sorted(rule_groups.items(), key=lambda x: -len(x[1]))[:MAX_SAST_PRS]
        print(f"[SAST] Processing {len(sorted_rules)} unique rule(s) in parallel...")

        # ── Parallel PR creation (one thread per rule) ──
        pr_results = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(_process_sast_rule, rule, rf, data, timestamp, token): rule
                for rule, rf in sorted_rules
            }
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    pr_results.append(result)

        # Update report
        report["sast"]["individual_prs"] = pr_results
        report["sast"]["pr_count"] = len(pr_results)
        for r in pr_results:
            if r.get("pr_url"):
                report["prs_created"].append({"type": "SAST", "url": r["pr_url"], "rule": r["rule"]})
        if pr_results:
            report["sast"]["pr_url"] = pr_results[0]["pr_url"]

        # ── Consolidated GitHub Issue ──
        high_crit = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        if high_crit and token:
            by_rule: Dict[str, List] = defaultdict(list)
            for f in high_crit:
                by_rule[f.get("rule", "unknown")].append(f)

            issue_body = f"## 🔴 SAST Security Findings — SonarQube\n\n"
            issue_body += f"**{len(high_crit)} HIGH/CRITICAL findings** | Build: {data.build_url}\n"
            issue_body += f"**{len(pr_results)} fix PR(s) created** (one per vulnerability type)\n\n"
            for rule, rfs in by_rule.items():
                display = _rule_display(rule, rfs[0].get("message", ""))
                matching = next((r for r in pr_results if r["rule"] == rule), None)
                pr_link = f"[Review PR]({matching['pr_url']})" if matching else "No PR"
                issue_body += f"### {display} ({len(rfs)}) | {pr_link}\n"
                for f in rfs[:5]:
                    issue_body += f"- `{f['file']}` line **{f.get('line','?')}**: {f['message']}\n"
                if len(rfs) > 5:
                    issue_body += f"- *...{len(rfs)-5} more*\n"
                issue_body += "\n"
            issue_body += "---\n*Security Orchestrator Bot*"

            try:
                r = requests.post(
                    f"{GITHUB_API}/repos/{data.repo_owner}/{data.repo_name}/issues",
                    headers=_gh_headers(token),
                    json={"title": f"[SECURITY-SAST] SonarQube {len(high_crit)} HIGH/CRITICAL findings",
                          "body": issue_body, "labels": ["security", "sast"]},
                    timeout=15,
                )
                if r.status_code in (200, 201):
                    iurl = r.json()["html_url"]
                    report["sast"]["issue_url"] = iurl
                    report["alerts_generated"].append({"type": "SAST", "url": iurl})
                    print(f"[SAST] ✅ Issue: {iurl}")
            except Exception as e:
                print(f"[SAST] Issue creation error: {e}")

        return findings

    except Exception as e:
        print(f"[SAST] Error: {e}")
        import traceback; traceback.print_exc()
        report["sast"].update({"status": "error", "reason": str(e)})
        return []


# ─────────────────────────────────────────────────────────────
# SCA — Snyk → PR
# ─────────────────────────────────────────────────────────────

def handle_sca(data, console_text: str, report: dict, timestamp: str):
    print("[SCA] Parsing Snyk findings...")
    findings = []
    lines = console_text.split("\n")
    sev_re = re.compile(r"\[(Low|Medium|High|Critical)\s+Severity\]\[(.+?)\]", re.IGNORECASE)
    intro_re = re.compile(r"introduced by\s+([^\s>]+)", re.IGNORECASE)

    for idx, line in enumerate(lines):
        if "[INFO]" in line and "Severity]" in line:
            m = sev_re.search(line)
            if not m:
                continue
            severity = m.group(1).upper()
            url = m.group(2).strip()
            inner = re.sub(r"^\[INFO\]\s+", "", line).strip()
            inner = re.sub(r"\s*\[.+", "", inner).strip()
            inner = re.sub(r"^[^a-zA-Z]+", "", inner).strip()
            pkg = "unknown"
            for j in range(idx + 1, min(idx + 4, len(lines))):
                pm = intro_re.search(lines[j])
                if pm:
                    pkg = pm.group(1).strip()
                    break
            findings.append({"tool": "snyk", "vulnerability": inner, "severity": severity,
                             "package": pkg, "url": url, "file": "pom.xml", "line": None, "code": pkg})

    report["sca"]["findings_count"] = len(findings)
    report["sca"]["status"] = "ok"
    print(f"[SCA] {len(findings)} finding(s)")

    if not findings:
        return
    high = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
    if high:
        pr_url = _create_pr_for_findings(high, "SCA", "Snyk", data, timestamp,
                                          "Upgrade vulnerable pom.xml dependencies to patched versions.")
        if pr_url:
            report["sca"]["pr_url"] = pr_url
            report["prs_created"].append({"type": "SCA", "url": pr_url})
            return
    issue_url = _create_github_issue_alert(findings, "SCA", "Snyk", data)
    if issue_url:
        report["sca"]["alert_url"] = issue_url
        report["alerts_generated"].append({"type": "SCA", "url": issue_url})


# ─────────────────────────────────────────────────────────────
# Container — Trivy → GitHub Issue
# ─────────────────────────────────────────────────────────────

def handle_container(data, console_text: str, report: dict, timestamp: str):
    print("[Container] Parsing Trivy findings...")
    findings = []
    lines = console_text.split("\n")
    vuln_re = re.compile(r"(Low|Medium|High|Critical)\s+severity vulnerability found in (.+)", re.IGNORECASE)
    cve_re = re.compile(r"Description:\s*(CVE-[^\s\r\n]+)", re.IGNORECASE)

    for idx, line in enumerate(lines):
        if "severity vulnerability found in" in line:
            v = vuln_re.search(line)
            if not v:
                continue
            severity, package = v.group(1).upper(), v.group(2).strip()
            cve = None
            for j in range(idx + 1, min(idx + 4, len(lines))):
                cm = cve_re.search(lines[j])
                if cm:
                    cve = cm.group(1).strip()
                    break
            if cve:
                findings.append({"tool": "trivy", "vulnerability": f"{cve} in {package}",
                                 "severity": severity, "package": package, "cve": cve,
                                 "file": "Dockerfile", "line": None, "code": package})

    report["container"]["findings_count"] = len(findings)
    report["container"]["status"] = "ok"
    print(f"[Container] {len(findings)} CVE(s)")

    if not findings:
        return
    issue_url = _create_github_issue_alert(findings, "Container", "Trivy", data)
    if issue_url:
        report["container"]["alert_url"] = issue_url
        report["alerts_generated"].append({"type": "Container", "url": issue_url})


# ─────────────────────────────────────────────────────────────
# DAST — ZAP → JSON report
# ─────────────────────────────────────────────────────────────

def handle_dast(data, report: dict, timestamp: str):
    workspace = getattr(data, "jenkins_workspace", None)
    report_path = getattr(data, "zap_report_path", None)
    if not report_path and workspace:
        report_path = os.path.join(workspace, "Output.html")
    if not report_path:
        report_path = r"C:\ProgramData\Jenkins\.jenkins\workspace\DevSecOpsEndtoEnd\Output.html"

    print(f"[DAST] Reading ZAP from: {report_path}")

    if not os.path.exists(report_path):
        report["dast"].update({"status": "report_not_found", "path_checked": report_path})
        return

    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()
        alerts = _parse_zap_html(html)
        report["dast"].update({"findings_count": len(alerts), "status": "ok", "alerts": alerts})
        print(f"[DAST] {len(alerts)} alert(s)")

        report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "data", "security_reports")
        os.makedirs(report_dir, exist_ok=True)
        dast_path = os.path.join(report_dir, f"{timestamp}_DAST_ZAP_{data.repo_name}.json")
        with open(dast_path, "w") as f:
            json.dump({"timestamp": timestamp, "tool": "ZAP", "type": "DAST",
                       "repo": f"{data.repo_owner}/{data.repo_name}", "alerts": alerts}, f, indent=2)
        report["dast"]["report_path"] = dast_path

        high_dast = [a for a in alerts if a.get("risk") in ("High", "Critical")]
        if high_dast:
            issue_url = _create_github_issue_alert(
                [{"tool": "ZAP", "vulnerability": a["alert"], "severity": a["risk"],
                  "file": a.get("url", ""), "line": None, "code": ""} for a in high_dast],
                "DAST", "OWASP ZAP", data)
            if issue_url:
                report["dast"]["alert_url"] = issue_url
                report["alerts_generated"].append({"type": "DAST", "url": issue_url})
    except Exception as e:
        print(f"[DAST] Error: {e}")
        report["dast"].update({"status": "error", "reason": str(e)})


def _parse_zap_html(html: str) -> List[Dict]:
    alerts = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for div in soup.find_all("div", class_="alert-type") or []:
            name = div.find("h3") or div.find("h2")
            risk = div.find("td", text=re.compile("Risk", re.I))
            alerts.append({
                "alert": name.text.strip() if name else "Unknown",
                "risk": risk.find_next_sibling("td").text.strip() if risk else "Unknown",
                "description": "", "url": "",
            })
    except Exception:
        pass
    if not alerts:
        for m in re.finditer(r"<h3>(.*?)</h3>.*?Risk.*?<td>(High|Medium|Low|Informational)</td>",
                              html, re.DOTALL | re.IGNORECASE):
            alerts.append({"alert": m.group(1).strip(), "risk": m.group(2).strip(),
                           "description": "", "url": ""})
    return alerts


# ─────────────────────────────────────────────────────────────
# IaC — Checkov → PR
# ─────────────────────────────────────────────────────────────

def handle_iac(data, console_text: str, report: dict, timestamp: str):
    print("[IaC] Parsing Checkov findings...")
    findings = []
    pattern = re.compile(
        r"Check:\s+(CKV[_A-Z0-9]+):\s+\"(.+?)\"\s+FAILED for resource:\s+(.+?)\s+File:\s+(\\[^\n]+)",
        re.MULTILINE)
    for m in pattern.finditer(console_text):
        check_id, check_name, resource, file_path = m.group(1).strip(), m.group(2).strip(), m.group(3).strip(), m.group(4).strip()
        sev = "HIGH" if any(k in check_name for k in ("IAM", "Wildcard", "*", "privilege")) else "MEDIUM"
        findings.append({"tool": "checkov", "vulnerability": f"{check_name} ({check_id})",
                         "severity": sev, "file": file_path, "resource": resource,
                         "check_id": check_id, "line": None, "code": f"Resource: {resource}"})

    report["iac"]["findings_count"] = len(findings)
    report["iac"]["status"] = "ok"
    print(f"[IaC] {len(findings)} finding(s)")

    if not findings:
        return
    pr_url = _create_pr_for_findings(findings, "IaC", "Checkov", data, timestamp,
                                      "Fix these Terraform misconfigurations in main.tf.")
    if pr_url:
        report["iac"]["pr_url"] = pr_url
        report["prs_created"].append({"type": "IaC", "url": pr_url})
    else:
        issue_url = _create_github_issue_alert(findings, "IaC", "Checkov", data)
        if issue_url:
            report["iac"]["alert_url"] = issue_url
            report["alerts_generated"].append({"type": "IaC", "url": issue_url})


# ─────────────────────────────────────────────────────────────
# Shared Helpers
# ─────────────────────────────────────────────────────────────

def _create_pr_for_findings(findings: List[Dict], scan_type: str, tool: str,
                              data, timestamp: str, pr_note: str = "") -> Optional[str]:
    """Create a single GitHub PR with AI analysis — used for SCA, IaC."""
    from app.github_integration import create_github_pr, push_file_update

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return None

    # Fast AI analysis (direct OpenAI, not LangGraph)
    findings_text = json.dumps(findings[:10], indent=2)
    prompt = (
        f"Security {scan_type} scan by {tool}. Analyze these findings:\n{findings_text}\n\n"
        f"For each: 1) Risk assessment 2) Specific fix with before/after code 3) Compliance impact "
        f"(SOC2/HIPAA/PCI-DSS). Be concise but complete."
    )
    analysis = _openai_analyze(prompt, max_tokens=2000) or f"Security findings from {tool}:\n\n{findings_text}"

    branch_name = f"fix/{scan_type.lower()}-{tool.lower()}-{timestamp}"
    pr_body = f"## {scan_type} Security Findings from {tool}\n\n"
    pr_body += f"**{len(findings)} issue(s) found** | Build: {data.build_url}\n\n"
    if pr_note:
        pr_body += f"> ℹ️ {pr_note}\n\n"
    pr_body += "---\n\n" + analysis

    report_md = (
        f"# Security {scan_type} Analysis — {tool}\n\n"
        f"**Build:** {data.build_url} | **Findings:** {len(findings)} | **Generated:** {timestamp}\n\n"
        f"## AI Analysis\n\n{analysis}\n\n"
        f"## Raw Findings\n\n```json\n{findings_text}\n```\n"
    )
    try:
        pushed = push_file_update(
            repo_owner=data.repo_owner, repo_name=data.repo_name,
            branch_name=branch_name, base_branch=data.branch,
            file_path=f"security-reports/{scan_type.lower()}-{tool.lower()}-{timestamp}.md",
            new_content=report_md,
            commit_message=f"[Security Bot] {scan_type} analysis — {len(findings)} finding(s)",
        )
        if not pushed:
            return None
    except Exception as e:
        print(f"[{scan_type}] push failed: {e}")
        return None

    try:
        return create_github_pr(
            repo_owner=data.repo_owner, repo_name=data.repo_name,
            branch_name=branch_name,
            title=f"[SECURITY-{scan_type}] {tool} findings — {len(findings)} issue(s)",
            body=pr_body, base_branch=data.branch,
        )
    except Exception as e:
        print(f"[{scan_type}] PR creation failed: {e}")
        return None


def _create_github_issue_alert(findings: List[Dict], scan_type: str, tool: str, data) -> Optional[str]:
    """Create a GitHub Issue alert."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return None

    by_sev: Dict[str, List] = {}
    for f in findings:
        by_sev.setdefault(f.get("severity", "MEDIUM"), []).append(f)

    body = f"## 🚨 {scan_type} Alert — {tool}\n\n**{len(findings)} findings** — manual review required.\n\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        grp = by_sev.get(sev, [])
        if grp:
            body += f"### {sev} ({len(grp)})\n"
            for f in grp[:15]:
                vuln = f.get("vulnerability", "Unknown")
                pkg = f.get("package", f.get("file", ""))
                body += f"- **{vuln}**" + (f" — `{pkg}`" if pkg else "") + "\n"
            body += "\n"
    body += "---\n*Security Orchestrator Bot*"

    try:
        r = requests.post(
            f"{GITHUB_API}/repos/{data.repo_owner}/{data.repo_name}/issues",
            headers=_gh_headers(token),
            json={"title": f"[SECURITY-{scan_type}] {tool} — {len(findings)} findings",
                  "body": body, "labels": ["security", scan_type.lower()]},
            timeout=15,
        )
        if r.status_code in (200, 201):
            url = r.json()["html_url"]
            print(f"[{scan_type}] ✅ Issue: {url}")
            return url
        print(f"[{scan_type}] Issue failed: {r.status_code}")
    except Exception as e:
        print(f"[{scan_type}] Issue error: {e}")
    return None


# ─────────────────────────────────────────────────────────────
# Save Pipeline Report
# ─────────────────────────────────────────────────────────────

def save_pipeline_report(report: dict, data, thread_id: str, timestamp: str) -> str:
    """Save the full pipeline report to disk and print URL prominently."""
    report_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "security_reports",
    )
    os.makedirs(report_dir, exist_ok=True)
    filename = f"{timestamp}_pipeline_{data.job_name}_{thread_id[:8]}.json"
    path = os.path.join(report_dir, filename)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    prs = report.get("prs_created", [])
    issues = report.get("alerts_generated", [])

    print("\n" + "═" * 65)
    print("  ✅  SECURITY PIPELINE COMPLETE")
    print("═" * 65)
    print(f"  SAST: {report.get('sast',{}).get('findings_count',0)} findings | "
          f"{report.get('sast',{}).get('pr_count',0)} PR(s)")
    print(f"  SCA:  {report.get('sca',{}).get('findings_count',0)} findings")
    print(f"  Container: {report.get('container',{}).get('findings_count',0)} CVEs")
    print(f"  IaC:  {report.get('iac',{}).get('findings_count',0)} failures")
    print(f"\n  📊 {len(prs)} PR(s) + {len(issues)} Issue(s) created on GitHub")
    for pr in prs:
        print(f"     🔀 [{pr['type']}] {pr['url']}")
    for iss in issues:
        print(f"     📌 [{iss['type']}] {iss['url']}")
    print("\n" + "─" * 65)
    print("  📋  REPORT URL  (share this with the team):")
    print(f"  http://localhost:8000/report/generate?pipeline_file={filename}")
    print("─" * 65)
    print("  🖨️  Export as PDF: open URL → Ctrl+P → Save as PDF")
    print("═" * 65 + "\n")

    return path
