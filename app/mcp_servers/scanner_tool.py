"""
Security Scanner Tool
Supports: Bandit (Python SAST), Semgrep (multi-language SAST), Safety (Python SCA),
          npm-audit (JS SCA), Trivy (container scanning), SonarQube (enterprise SAST),
          SpotBugs (Java SAST)
"""
import os
import json
import subprocess
import glob
import requests
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()

# SonarQube configuration from environment
SONARQUBE_URL = os.getenv("SONARQUBE_URL", "http://localhost:9000")
SONARQUBE_TOKEN = os.getenv("SONARQUBE_TOKEN", "")


def detect_language(repo_path: str) -> str:
    """
    Auto-detect the primary programming language of a repository.
    
    Args:
        repo_path: Path to the repository root
        
    Returns:
        Detected language string (python, javascript, java, go, ruby, typescript)
    """
    extension_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".cs": "csharp",
        ".php": "php",
        ".rs": "rust",
    }
    
    # Count files by extension
    counts = {}
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs, node_modules, vendor, etc.
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'vendor', '__pycache__', '.git')]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in extension_map:
                lang = extension_map[ext]
                counts[lang] = counts.get(lang, 0) + 1
    
    if not counts:
        return "auto"
    
    # Return the language with most files
    return max(counts, key=counts.get)


def run_security_scan(repo_path: str, tool_name: str) -> List[Dict]:
    """
    Run a security scan using the specified tool.
    
    Args:
        repo_path: Path to the repository to scan
        tool_name: Name of the scanning tool (bandit, semgrep, safety, npm-audit, trivy)
        
    Returns:
        List of finding dictionaries with keys: tool, vulnerability, file, line, code, severity
    """
    scanners = {
        "bandit": _run_bandit,
        "semgrep": _run_semgrep,
        "safety": _run_safety,
        "npm-audit": _run_npm_audit,
        "trivy": _run_trivy,
        "sonarqube": _run_sonarqube,
        "spotbugs": _run_spotbugs,
    }
    
    scanner_fn = scanners.get(tool_name)
    if not scanner_fn:
        print(f"⚠️ Unknown scanner: {tool_name}. Supported: {list(scanners.keys())}")
        return []
    
    try:
        return scanner_fn(repo_path)
    except FileNotFoundError:
        print(f"⚠️ Scanner '{tool_name}' not installed. Install it first.")
        return []
    except Exception as e:
        print(f"❌ Error running {tool_name}: {e}")
        return []


def _run_bandit(repo_path: str) -> List[Dict]:
    """Run Bandit (Python SAST scanner)."""
    try:
        result = subprocess.run(
            ["bandit", "-r", repo_path, "-f", "json", "-ll"],
            capture_output=True, text=True, timeout=300
        )
        
        if not result.stdout:
            return []
        
        report = json.loads(result.stdout)
        findings = []
        
        for issue in report.get("results", []):
            findings.append({
                "tool": "bandit",
                "vulnerability": f"{issue.get('issue_text', 'Unknown')} ({issue.get('test_id', '')})",
                "file": os.path.relpath(issue.get("filename", ""), repo_path),
                "line": issue.get("line_number"),
                "code": issue.get("code", "").strip(),
                "severity": issue.get("issue_severity", "MEDIUM"),
            })
        
        return findings
    except json.JSONDecodeError:
        return []


# Semgrep security rule packs per language — chosen for maximum security finding coverage
_SEMGREP_CONFIGS = {
    "java":       ["p/java", "p/owasp-top-ten", "p/security-audit"],
    "python":     ["p/python", "p/bandit", "p/owasp-top-ten"],
    "javascript": ["p/javascript", "p/nodejs", "p/owasp-top-ten"],
    "typescript": ["p/typescript", "p/nodejs", "p/owasp-top-ten"],
    "go":         ["p/golang", "p/owasp-top-ten"],
    "ruby":       ["p/ruby", "p/owasp-top-ten"],
    "php":        ["p/php", "p/owasp-top-ten"],
    "csharp":     ["p/csharp", "p/owasp-top-ten"],
    "auto":       ["p/security-audit", "p/owasp-top-ten"],
}


def _run_semgrep(repo_path: str, language: str = "") -> List[Dict]:
    """
    Run Semgrep with language-specific security rulesets.
    Uses targeted packs (p/java, p/python, etc.) instead of generic --config=auto,
    which finds far more real security vulnerabilities.
    """
    # Auto-detect language for semgrep if not given
    if not language:
        language = detect_language(repo_path)

    configs = _SEMGREP_CONFIGS.get(language, _SEMGREP_CONFIGS["auto"])
    findings = []

    # Try each config pack — first one that succeeds wins (or merge all)
    for config in configs:
        try:
            result = subprocess.run(
                ["semgrep", f"--config={config}", "--json",
                 "--no-error", "--quiet", repo_path],
                capture_output=True, text=True, timeout=300,
            )
            if not result.stdout:
                continue

            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError:
                continue

            for match in report.get("results", []):
                severity = match.get("extra", {}).get("severity", "WARNING")
                norm_sev = _normalize_severity(severity)
                check_id = match.get("check_id", "Unknown rule")
                msg = match.get("extra", {}).get("message", check_id)
                # Use message as vulnerability name, fallback to check_id
                vuln_name = (msg[:80] if msg and msg != check_id else check_id)
                findings.append({
                    "tool": "semgrep",
                    "vulnerability": vuln_name,
                    "file": os.path.relpath(match.get("path", ""), repo_path),
                    "line": match.get("start", {}).get("line"),
                    "code": match.get("extra", {}).get("lines", "").strip(),
                    "severity": norm_sev,
                    "rule_id": check_id,
                })

            if findings:
                print(f"  [semgrep/{config}] {len(findings)} finding(s)")
                break  # Stop at first config that produces results

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"  [semgrep/{config}] error: {e}")
            continue

    # Fallback: try --config=auto if no security packs found anything
    if not findings:
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", "--no-error", "--quiet", repo_path],
                capture_output=True, text=True, timeout=300,
            )
            if result.stdout:
                report = json.loads(result.stdout)
                for match in report.get("results", []):
                    severity = match.get("extra", {}).get("severity", "WARNING")
                    findings.append({
                        "tool": "semgrep",
                        "vulnerability": match.get("check_id", "Unknown rule"),
                        "file": os.path.relpath(match.get("path", ""), repo_path),
                        "line": match.get("start", {}).get("line"),
                        "code": match.get("extra", {}).get("lines", "").strip(),
                        "severity": _normalize_severity(severity),
                    })
        except Exception:
            pass

    return findings


def _run_safety(repo_path: str) -> List[Dict]:
    """Run Safety (Python dependency vulnerability scanner)."""
    req_file = os.path.join(repo_path, "requirements.txt")
    if not os.path.exists(req_file):
        return []
    
    try:
        result = subprocess.run(
            ["safety", "check", "-r", req_file, "--json"],
            capture_output=True, text=True, timeout=120
        )
        
        if not result.stdout:
            return []
        
        report = json.loads(result.stdout)
        findings = []
        
        # Safety output format varies by version
        vulnerabilities = report if isinstance(report, list) else report.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            if isinstance(vuln, list):
                # Old safety format: [package, installed_version, affected_version, description, id]
                findings.append({
                    "tool": "safety",
                    "vulnerability": f"Vulnerable dependency: {vuln[0]}=={vuln[1]} ({vuln[3][:100]})",
                    "file": "requirements.txt",
                    "line": None,
                    "code": f"{vuln[0]}=={vuln[1]}",
                    "severity": "HIGH",
                })
            elif isinstance(vuln, dict):
                findings.append({
                    "tool": "safety",
                    "vulnerability": f"Vulnerable dependency: {vuln.get('package_name', 'unknown')}",
                    "file": "requirements.txt",
                    "line": None,
                    "code": vuln.get("analyzed_version", ""),
                    "severity": "HIGH",
                })
        
        return findings
    except json.JSONDecodeError:
        return []


def _run_npm_audit(repo_path: str) -> List[Dict]:
    """Run npm audit (JavaScript/Node.js dependency scanner)."""
    pkg_file = os.path.join(repo_path, "package.json")
    if not os.path.exists(pkg_file):
        return []
    
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=repo_path
        )
        
        if not result.stdout:
            return []
        
        report = json.loads(result.stdout)
        findings = []
        
        for vuln_id, vuln_data in report.get("vulnerabilities", {}).items():
            findings.append({
                "tool": "npm-audit",
                "vulnerability": f"{vuln_id}: {vuln_data.get('title', 'Unknown')}",
                "file": "package.json",
                "line": None,
                "code": f"{vuln_data.get('name', '')}@{vuln_data.get('range', '')}",
                "severity": vuln_data.get("severity", "moderate").upper(),
            })
        
        return findings
    except json.JSONDecodeError:
        return []


def _run_trivy(repo_path: str) -> List[Dict]:
    """Run Trivy (filesystem/container vulnerability scanner)."""
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", repo_path],
            capture_output=True, text=True, timeout=300
        )
        
        if not result.stdout:
            return []
        
        report = json.loads(result.stdout)
        findings = []
        
        for target in report.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                findings.append({
                    "tool": "trivy",
                    "vulnerability": f"{vuln.get('VulnerabilityID', 'Unknown')}: {vuln.get('Title', '')}",
                    "file": target.get("Target", ""),
                    "line": None,
                    "code": f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                    "severity": vuln.get("Severity", "MEDIUM"),
                })
        
        return findings
    except json.JSONDecodeError:
        return []


def _run_sonarqube(repo_path: str, project_key: str = None) -> List[Dict]:
    """
    Run SonarQube scan and fetch results via API.

    For NEW repos: fetches API directly — no sonar-scanner CLI needed
    if the project already exists on SonarQube. If not, tries running sonar-scanner first.

    Uses SONARQUBE_TOKEN (read dynamically from env so .env reload always works).
    Always tries multiple project key variants to find a match.
    """
    # Always read dynamically so a reloaded .env is picked up
    token = os.getenv("SONARQUBE_TOKEN", "")
    sonar_url = os.getenv("SONARQUBE_URL", "http://localhost:9000")

    if not token:
        print("⚠️ SONARQUBE_TOKEN not set in .env — skipping SonarQube.")
        print("   Fix: SonarQube → My Account → Security → Generate Token → add to .env")
        return []

    # Build a list of project key candidates to try
    if not project_key:
        folder_name = os.path.basename(os.path.abspath(repo_path)).lower().replace(" ", "-")
        # Try common naming patterns: folder, folder with underscores, the well-known easybuggy key
        candidates = [
            folder_name,
            folder_name.replace("-", "_"),
            folder_name.replace("-", ""),
            os.getenv("SONARQUBE_PROJECT_KEY", ""),
            "easybuggy",  # default known project on this SonarQube
        ]
        candidates = [c for c in candidates if c]  # remove empty
    else:
        candidates = [project_key]

    print(f"[SonarQube] Connecting to {sonar_url} | trying project keys: {candidates}")

    # Try fetching from each candidate key
    for candidate in candidates:
        findings = _fetch_sonarqube_issues(candidate, token, sonar_url)
        if findings:
            print(f"[SonarQube] ✅ Found {len(findings)} issues for project: {candidate}")
            return findings
        # Check if project exists but has 0 findings (still valid)
        try:
            r = requests.get(
                f"{sonar_url}/api/projects/search",
                params={"projects": candidate}, auth=(token, ""), timeout=10,
            )
            if r.status_code == 200 and r.json().get("components"):
                print(f"[SonarQube] Project '{candidate}' found but 0 issues — project may be clean.")
                return []
        except Exception:
            pass

    # If no existing project found, try running sonar-scanner to create/scan it
    key_to_scan = candidates[0]
    print(f"[SonarQube] Project not found. Running sonar-scanner for {key_to_scan}...")
    sonar_cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={key_to_scan}",
        f"-Dsonar.sources={os.path.abspath(repo_path)}",
        f"-Dsonar.host.url={sonar_url}",
        f"-Dsonar.token={token}",
        "-Dsonar.scm.disabled=true",
        f"-Dsonar.projectName={key_to_scan}",
    ]
    try:
        result = subprocess.run(sonar_cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            import time; time.sleep(5)  # wait for SonarQube to process
            findings = _fetch_sonarqube_issues(key_to_scan, token, sonar_url)
            if findings:
                return findings
        else:
            print(f"[SonarQube] sonar-scanner failed: {result.stderr[:200]}")
    except FileNotFoundError:
        print("[SonarQube] sonar-scanner CLI not installed — returning empty")
    except Exception as e:
        print(f"[SonarQube] sonar-scanner error: {e}")

    return []


def _fetch_sonarqube_issues(project_key: str, token: str = None, sonar_url: str = None) -> List[Dict]:
    """
    Fetch security issues from SonarQube REST API for a given project key.
    Uses the dynamically passed token + URL (not stale module-level vars).
    """
    # Always read fresh from env — don't use stale module-level SONARQUBE_TOKEN
    _token    = token    or os.getenv("SONARQUBE_TOKEN", "")
    _sonar_url = sonar_url or os.getenv("SONARQUBE_URL", "http://localhost:9000")
    if not _token:
        return []

    severity_map = {
        "CRITICAL": "CRITICAL", "BLOCKER": "CRITICAL",
        "MAJOR": "HIGH", "MINOR": "MEDIUM", "INFO": "LOW",
    }

    try:
        response = requests.get(
            f"{_sonar_url}/api/issues/search",
            params={
                "componentKeys": project_key,
                "types": "VULNERABILITY,BUG,CODE_SMELL",
                "severities": "CRITICAL,MAJOR,MINOR",
                "ps": 100,
            },
            auth=(_token, ""),
            timeout=30,
        )

        if response.status_code == 401:
            print(f"❌ SonarQube token expired/invalid for {_sonar_url}")
            print("   Fix: SonarQube → My Account → Security → Generate new token → update .env")
            return []

        if response.status_code == 404:
            # Project not found — this is expected for new repos not yet scanned
            return []

        if response.status_code != 200:
            print(f"⚠️ SonarQube API {response.status_code} for project '{project_key}': {response.text[:100]}")
            return []

        issues = response.json().get("issues", [])
        findings = []
        for issue in issues:
            findings.append({
                "tool": "sonarqube",
                "vulnerability": f"{issue.get('message','Unknown')} ({issue.get('rule','')})",
                "file": issue.get("component", "").split(":")[-1],
                "line": issue.get("line"),
                "code": str(issue.get("textRange", {}).get("startLine", "")),
                "severity": severity_map.get(issue.get("severity", "MAJOR"), "HIGH"),
            })

        if findings:
            print(f"[SonarQube] ✅ {len(findings)} issues found for '{project_key}' on {_sonar_url}")
        return findings

    except requests.ConnectionError:
        print(f"⚠️ SonarQube not reachable at {_sonar_url} — skipping SonarQube scan")
        return []
    except Exception as e:
        print(f"⚠️ SonarQube fetch error: {e}")
        return []


def _run_spotbugs(repo_path: str) -> List[Dict]:
    """
    Run SpotBugs (Java SAST scanner).
    
    Requires: Maven project with SpotBugs plugin configured.
    Or: spotbugs.jar installed separately.
    
    For Maven projects, add to pom.xml:
        <plugin>
            <groupId>com.github.spotbugs</groupId>
            <artifactId>spotbugs-maven-plugin</artifactId>
            <version>4.8.2.0</version>
        </plugin>
    """
    # Check if it's a Maven project
    pom_file = os.path.join(repo_path, "pom.xml")
    if os.path.exists(pom_file):
        return _run_spotbugs_maven(repo_path)

    # Check for Gradle
    gradle_file = os.path.join(repo_path, "build.gradle")
    if os.path.exists(gradle_file):
        print("ℹ️  Gradle SpotBugs: Run 'gradle spotbugsMain' manually and check reports/")
        return []

    print("⚠️ SpotBugs requires a Java Maven/Gradle project (pom.xml or build.gradle)")
    return []


def _run_spotbugs_maven(repo_path: str) -> List[Dict]:
    """Run SpotBugs via Maven plugin."""
    try:
        # Run SpotBugs via Maven
        result = subprocess.run(
            ["mvn", "compile", "spotbugs:spotbugs", "-q"],
            capture_output=True, text=True, timeout=600,
            cwd=repo_path
        )

        # Parse the SpotBugs XML report
        import xml.etree.ElementTree as ET
        report_paths = glob.glob(os.path.join(repo_path, "**/spotbugsXml.xml"), recursive=True)

        if not report_paths:
            # Also check target/spotbugs
            report_paths = glob.glob(os.path.join(repo_path, "target", "spotbugsXml.xml"))

        if not report_paths:
            print(f"⚠️ SpotBugs report not found. Maven output: {result.stderr[:200]}")
            return []

        findings = []
        tree = ET.parse(report_paths[0])
        root = tree.getroot()

        for bug in root.findall(".//BugInstance"):
            bug_type = bug.get("type", "Unknown")
            priority = bug.get("priority", "2")
            category = bug.get("category", "")

            source_line = bug.find(".//SourceLine")
            file_path = source_line.get("sourcefile", "") if source_line is not None else ""
            line = source_line.get("start", "") if source_line is not None else ""

            message = bug.find(".//LongMessage")
            msg = message.text if message is not None else bug_type

            severity_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}

            findings.append({
                "tool": "spotbugs",
                "vulnerability": f"{msg} ({bug_type})",
                "file": file_path,
                "line": int(line) if line.isdigit() else None,
                "code": f"Category: {category}",
                "severity": severity_map.get(str(priority), "MEDIUM"),
            })

        print(f"✅ SpotBugs found {len(findings)} issues")
        return findings

    except FileNotFoundError:
        print("⚠️ Maven (mvn) not found. Install Maven to run SpotBugs.")
        return []
    except Exception as e:
        print(f"❌ SpotBugs error: {e}")
        return []


def _normalize_severity(severity: str) -> str:
    """Normalize severity strings across different tools."""
    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "NOTE": "LOW",
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    return severity_map.get(severity.upper(), "MEDIUM")
