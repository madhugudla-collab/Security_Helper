import os
import requests
import base64
from typing import Optional
from dotenv import load_dotenv

load_dotenv()  # ← FIX: Load .env at module level so token is available


def _get_token():
    """Always read fresh token from environment (supports .env reload)."""
    return os.getenv("GITHUB_TOKEN")


GITHUB_API = "https://api.github.com"


def _get_default_branch(repo_owner: str, repo_name: str, headers: dict) -> str:
    """Auto-detect repo default branch (main or master or other)."""
    resp = requests.get(
        f"{GITHUB_API}/repos/{repo_owner}/{repo_name}",
        headers=headers
    )
    if resp.status_code == 200:
        return resp.json().get("default_branch", "main")
    return "main"


def push_file_update(
    repo_owner: str,
    repo_name: str,
    branch_name: str,
    base_branch: str,
    file_path: str,
    new_content: str,
    commit_message: str
) -> bool:
    """Creates a branch and pushes a file update via GitHub API"""
    GITHUB_TOKEN = _get_token()
    if not GITHUB_TOKEN:
        print("❌ GITHUB_TOKEN not set in environment")
        return False

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    # FIX: Auto-detect real default branch if "main" fails
    ref_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
    resp = requests.get(ref_url, headers=headers)
    if resp.status_code != 200:
        # Try auto-detecting the real default branch
        detected = _get_default_branch(repo_owner, repo_name, headers)
        print(f"⚠️  Branch '{base_branch}' not found, trying detected default branch: '{detected}'")
        base_branch = detected
        ref_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
        resp = requests.get(ref_url, headers=headers)
        if resp.status_code != 200:
            print(f"❌ Could not find base branch '{base_branch}' (status: {resp.status_code})")
            print(f"   Make sure your token has access to {repo_owner}/{repo_name}")
            return False

    base_sha = resp.json()["object"]["sha"]

    # Create new branch (ignore error if already exists)
    create_resp = requests.post(
        f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
    )
    if create_resp.status_code not in [200, 201, 422]:
        print(f"⚠️  Branch creation status: {create_resp.status_code}")

    # Get file SHA if it exists (needed to update an existing file)
    file_url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    resp = requests.get(file_url, headers=headers, params={"ref": branch_name})
    file_sha = resp.json().get("sha") if resp.status_code == 200 else None

    # Push the content
    content_b64 = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
    data = {
        "message": commit_message,
        "content": content_b64,
        "branch": branch_name
    }
    if file_sha:
        data["sha"] = file_sha

    put_resp = requests.put(file_url, headers=headers, json=data)
    if put_resp.status_code in [200, 201]:
        print(f"✅ Pushed fix to branch {branch_name}")
        return True
    else:
        print(f"❌ Failed to push code: {put_resp.status_code} - {put_resp.text[:200]}")
        return False


def create_github_pr(
    repo_owner: str,
    repo_name: str,
    branch_name: str,
    title: str,
    body: str,
    base_branch: str = "main"
) -> Optional[str]:
    """Create a GitHub PR with the recommended fix. Auto-detects default branch."""
    GITHUB_TOKEN = _get_token()
    if not GITHUB_TOKEN:
        print("❌ GITHUB_TOKEN not set in environment")
        return None

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    # FIX: Auto-detect the real default branch
    real_base = _get_default_branch(repo_owner, repo_name, headers)
    if real_base != base_branch:
        print(f"ℹ️  Using detected default branch '{real_base}' instead of '{base_branch}'")
        base_branch = real_base

    url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/pulls"
    data = {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": base_branch
    }

    try:
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 422 and "pull request already exists" in response.text.lower():
            print("⚠️  PR already exists.")
            return None
        response.raise_for_status()
        pr_url = response.json()["html_url"]
        print(f"✅ Created PR: {pr_url}")
        return pr_url
    except Exception as e:
        print(f"❌ Failed to create PR: {e}")
        return None


def post_pr_comment(
    repo_owner: str,
    repo_name: str,
    pr_number: int,
    comment: str
) -> bool:
    """Post a comment on an existing PR"""
    GITHUB_TOKEN = _get_token()
    if not GITHUB_TOKEN:
        return False

    url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.post(url, json={"body": comment}, headers=headers)
        response.raise_for_status()
        print(f"✅ Posted comment on PR #{pr_number}")
        return True
    except Exception as e:
        print(f"❌ Failed to post comment: {e}")
        return False
