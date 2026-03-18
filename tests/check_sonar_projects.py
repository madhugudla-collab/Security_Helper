#!/usr/bin/env python3
"""Check SonarQube connectivity and list projects to find the right project key."""
import os, sys, requests
sys.path.insert(0, "..")
from dotenv import load_dotenv
load_dotenv()

sonar_url   = os.getenv("SONARQUBE_URL", "http://localhost:9000")
sonar_token = os.getenv("SONARQUBE_TOKEN", "")
headers     = {"Authorization": f"Bearer {sonar_token}"}

print(f"\nSonarQube URL: {sonar_url}")
print(f"Token:         {sonar_token[:12]}...\n")

# 1. Test connectivity
try:
    r = requests.get(f"{sonar_url}/api/system/status", headers=headers, timeout=5)
    print(f"System status: {r.status_code} — {r.json()}")
except Exception as e:
    print(f"Cannot connect to SonarQube: {e}")
    print("SonarQube may not be running. The HTML report will use PR data as stubs.")
    sys.exit(0)

# 2. List all projects
try:
    r = requests.get(f"{sonar_url}/api/projects/search?ps=50", headers=headers, timeout=10)
    projects = r.json().get("components", [])
    print(f"\nProjects found ({len(projects)}):")
    for p in projects:
        print(f"  key={p['key']}  name={p['name']}")
except Exception as e:
    print(f"Error listing projects: {e}")

# 3. Try to fetch issues for the devsecops repo
target_keys = [
    "devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
    "madhugudla-collab:devsecops-jenkins-sast-sca-iac-cs-dast-e2e-repo",
    "easybuggy",
]
print(f"\nTesting project key lookups:")
for pk in target_keys:
    import urllib.parse
    url = f"{sonar_url}/api/issues/search?componentKeys={urllib.parse.quote(pk)}&resolved=false&ps=5"
    try:
        r = requests.get(url, headers=headers, timeout=8)
        d = r.json()
        print(f"  key={pk!r}: HTTP {r.status_code}, total={d.get('total', 'N/A')}, issues={len(d.get('issues',[]))}")
    except Exception as e:
        print(f"  key={pk!r}: ERROR {e}")
