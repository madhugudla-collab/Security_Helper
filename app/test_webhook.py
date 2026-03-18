"""
Test scripts for the Security Orchestrator Bot.
Tests all API endpoints: webhook, scan, onboard, logs, health.

Usage:
    1. Start the server:  uvicorn app.main:app --reload
    2. Run this script:   python -m app.test_webhook
"""
import requests
import json
import sys

API_BASE = "http://localhost:8000"


def test_health():
    """Test health check endpoint."""
    print("\n" + "="*50)
    print("TEST: Health Check")
    print("="*50)
    try:
        resp = requests.get(f"{API_BASE}/health")
        print(f"Status: {resp.status_code}")
        print(json.dumps(resp.json(), indent=2))
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running. Start with: uvicorn app.main:app --reload")
        return False


def test_webhook_jenkins():
    """Test Jenkins webhook with sample security findings."""
    print("\n" + "="*50)
    print("TEST: Jenkins Webhook - SQL Injection Finding")
    print("="*50)

    payload = {
        "name": "nightly-security-scan",
        "job_name": "backend-service-auth",
        "build_url": "http://jenkins.internal/job/backend-service-auth/42",
        "branch": "develop",
        "repo_owner": "madhugudla-collab",
        "repo_name": "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
        "build": {
            "full_url": "http://jenkins.internal/job/backend-service-auth/42",
            "log": "Build failed. Security scan returned critical issues.",
        },
        "reports": [
            {
                "tool": "SonarQube",
                "findings": {
                    "vulnerability": "SQL Injection",
                    "file": "app/auth/login.py",
                    "line": 45,
                    "code": 'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'")',
                    "severity": "CRITICAL",
                },
            }
        ],
    }

    try:
        resp = requests.post(f"{API_BASE}/webhook/jenkins", json=payload)
        print(f"Status: {resp.status_code}")
        print(json.dumps(resp.json(), indent=2))
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        return False


def test_webhook_multi_findings():
    """Test webhook with multiple security findings from different tools."""
    print("\n" + "="*50)
    print("TEST: Jenkins Webhook - Multiple Findings")
    print("="*50)

    payload = {
        "name": "full-security-scan",
        "job_name": "security-scan",
        "build_url": "http://jenkins.internal/job/security-scan/10",
        "branch": "main",
        "repo_owner": "madhugudla-collab",
        "repo_name": "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
        "build": {
            "full_url": "http://jenkins.internal/job/security-scan/10",
            "log": "Multiple security issues detected.",
        },
        "reports": [
            {
                "tool": "bandit",
                "findings": {
                    "vulnerability": "Hardcoded password detected (B105)",
                    "file": "config/settings.py",
                    "line": 12,
                    "code": 'DB_PASSWORD = "admin123"',
                    "severity": "HIGH",
                },
            },
            {
                "tool": "semgrep",
                "findings": {
                    "vulnerability": "python.lang.security.audit.exec-detected",
                    "file": "app/utils/runner.py",
                    "line": 23,
                    "code": "exec(user_input)",
                    "severity": "CRITICAL",
                },
            },
        ],
    }

    try:
        resp = requests.post(f"{API_BASE}/webhook/jenkins", json=payload)
        print(f"Status: {resp.status_code}")
        print(json.dumps(resp.json(), indent=2))
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        return False


def test_onboard_repo():
    """Test onboarding a new repository."""
    print("\n" + "="*50)
    print("TEST: Onboard New Repository")
    print("="*50)

    payload = {
        "repo_owner": "example-org",
        "repo_name": "vulnerable-app",
        "branch": "main",
        "language": "python",
    }

    try:
        resp = requests.post(f"{API_BASE}/onboard", json=payload)
        print(f"Status: {resp.status_code}")
        data = resp.json()
        print(f"Repo: {data.get('repo')}")
        print(f"Scan Tools: {data.get('scan_tools')}")
        print(f"Instructions: {json.dumps(data.get('instructions'), indent=2)}")
        print(f"\nGenerated Jenkinsfile (first 500 chars):\n{data.get('jenkinsfile', '')[:500]}...")
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        return False


def test_list_logs():
    """Test listing security reports."""
    print("\n" + "="*50)
    print("TEST: List Security Reports")
    print("="*50)

    try:
        resp = requests.get(f"{API_BASE}/logs")
        print(f"Status: {resp.status_code}")
        logs = resp.json()
        print(f"Found {len(logs)} report(s)")
        for log in logs[:5]:
            print(f"  - {log}")
        return resp.status_code == 200
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        return False


def test_path_traversal_protection():
    """Test that path traversal is blocked on logs endpoint."""
    print("\n" + "="*50)
    print("TEST: Path Traversal Protection")
    print("="*50)

    try:
        resp = requests.get(f"{API_BASE}/logs/../../.env")
        print(f"Status: {resp.status_code} (expected 400)")
        return resp.status_code == 400
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  Security Orchestrator Bot - Test Suite")
    print("=" * 60)

    tests = [
        ("Health Check", test_health),
        ("Jenkins Webhook", test_webhook_jenkins),
        ("Multi-Finding Webhook", test_webhook_multi_findings),
        ("Onboard Repository", test_onboard_repo),
        ("List Logs", test_list_logs),
        ("Path Traversal Protection", test_path_traversal_protection),
    ]

    results = []
    for name, test_fn in tests:
        try:
            passed = test_fn()
            results.append((name, passed))
        except Exception as e:
            print(f"ERROR: {e}")
            results.append((name, False))

    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        emoji = "✅" if passed else "❌"
        print(f"  {emoji} {name}: {status}")

    all_passed = all(p for _, p in results)
    print(f"\n{'All tests passed!' if all_passed else 'Some tests failed.'}")
    sys.exit(0 if all_passed else 1)
