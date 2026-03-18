"""
Code Fix Agents Integration
Supports: OpenAI Codex, Corgea, GitHub Copilot
"""
import os
import json
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

# Codex Agent (OpenAI's code-specialized model)
codex_llm = ChatOpenAI(model="gpt-4", temperature=0)


@tool
def generate_code_fix(vulnerability_description: str, file_path: str, vulnerable_code: str) -> str:
    """
    Uses OpenAI Codex to generate secure code fix for vulnerabilities.

    Args:
        vulnerability_description: Description of the security issue
        file_path: Path to the vulnerable file
        vulnerable_code: The actual vulnerable code snippet

    Returns:
        Fixed code with explanation
    """
    prompt = f"""You are a security code fix expert. Generate a secure fix for this vulnerability.

Vulnerability: {vulnerability_description}
File: {file_path}

Vulnerable Code:
```
{vulnerable_code}
```

Provide:
1. Fixed code (secure implementation)
2. Explanation of what was fixed
3. Security best practices applied

Format as:
FIXED CODE:
```
[secure code here]
```

EXPLANATION:
[explanation here]

SECURITY MEASURES:
- [measure 1]
- [measure 2]
"""
    response = codex_llm.invoke(prompt)
    return response.content


@tool
def corgea_fix_vulnerability(vulnerability_type: str, vulnerable_code: str, file_path: str) -> str:
    """
    Uses Corgea API to generate automated security fixes.

    Args:
        vulnerability_type: Type of vulnerability (e.g. SQL Injection, XSS)
        vulnerable_code: The vulnerable code snippet
        file_path: Path to the file with vulnerability

    Returns:
        Corgea-generated fix recommendation
    """
    corgea_api_key = os.getenv("CORGEA_API_KEY")
    if not corgea_api_key:
        # Fallback to GPT-4 based fix when Corgea is not configured
        prompt = f"""You are a Corgea-style automated security remediation engine.
Analyze and fix this {vulnerability_type} vulnerability.

File: {file_path}
Vulnerable Code:
```
{vulnerable_code}
```

Provide:
1. Root cause analysis
2. Automated fix (production-ready code)
3. Confidence score (0-100%)
4. Alternative fixes if applicable
"""
        response = codex_llm.invoke(prompt)
        return f"[Corgea Fallback - GPT-4 Analysis]\n{response.content}"

    # TODO: Integrate with actual Corgea API when key is available
    # import requests
    # response = requests.post(
    #     "https://api.corgea.com/v1/fix",
    #     headers={"Authorization": f"Bearer {corgea_api_key}"},
    #     json={
    #         "vulnerability_type": vulnerability_type,
    #         "code": vulnerable_code,
    #         "file_path": file_path
    #     }
    # )
    # return response.json()["fix"]

    return "Corgea integration pending - API key configured but endpoint not yet implemented"


@tool
def github_copilot_suggest_fix(code_context: str, issue_description: str) -> str:
    """
    Uses GitHub Copilot-style prompting to suggest fixes.

    Args:
        code_context: Surrounding code context
        issue_description: Description of the issue

    Returns:
        Suggested fix
    """
    prompt = f"""# Fix the following security issue:
# Issue: {issue_description}

# Current code:
{code_context}

# Secure implementation:
"""
    response = codex_llm.invoke(prompt)
    return response.content
