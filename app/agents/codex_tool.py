"""
OpenAI Codex Tool (using GPT-4 - Codex successor)
Specialized for generating secure code fixes
"""
import os
from openai import OpenAI
from langchain_core.tools import tool

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

@tool
def codex_generate_fix(
    vulnerability_type: str,
    vulnerable_code: str,
    file_path: str,
    language: str = "python"
) -> str:
    """
    Uses OpenAI Codex (GPT-4) to generate secure code fixes for vulnerabilities.
    
    Args:
        vulnerability_type: Type of vulnerability (e.g., "SQL Injection", "XSS")
        vulnerable_code: The insecure code snippet
        file_path: Path to the file with vulnerability
        language: Programming language (default: python)
    
    Returns:
        Secure code fix with explanation
    """
    
    prompt = f"""You are an expert security engineer. Fix this {vulnerability_type} vulnerability.

File: {file_path}
Language: {language}

VULNERABLE CODE:
```{language}
{vulnerable_code}
```

Provide:
1. SECURE CODE (fixed version)
2. EXPLANATION (what changed and why)
3. TESTING (how to verify the fix)

Format:
## SECURE CODE
```{language}
[fixed code here]
```

## EXPLANATION
[detailed explanation]

## TESTING
[test cases to verify fix]
"""

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": "You are a security code fix expert. Generate production-ready secure code."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2,  # Low temperature for consistent, secure code
        max_tokens=2000
    )
    
    return response.choices[0].message.content


@tool
def codex_analyze_vulnerability(security_finding: str) -> str:
    """
    Uses Codex to analyze security findings and provide detailed risk assessment.
    
    Args:
        security_finding: JSON string of security scan finding
    
    Returns:
        Detailed vulnerability analysis
    """
    
    prompt = f"""Analyze this security vulnerability finding:

{security_finding}

Provide:
1. SEVERITY ASSESSMENT (Critical/High/Medium/Low and why)
2. ATTACK VECTOR (how it can be exploited)
3. BUSINESS IMPACT (what could happen)
4. COMPLIANCE IMPACT (SOC2/HIPAA/PCI-DSS violations)
5. REMEDIATION PRIORITY (immediate/urgent/scheduled)
"""

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": "You are a security analyst expert in vulnerability assessment."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3,
        max_tokens=1500
    )
    
    return response.choices[0].message.content


@tool
def codex_create_pr_description(
    vulnerability_summary: str,
    code_fix: str,
    compliance_requirements: str
) -> str:
    """
    Uses Codex to create comprehensive GitHub PR description.
    
    Args:
        vulnerability_summary: Summary of vulnerabilities fixed
        code_fix: The code changes made
        compliance_requirements: Relevant compliance requirements
    
    Returns:
        Formatted GitHub PR description
    """
    
    prompt = f"""Create a GitHub Pull Request description for this security fix:

VULNERABILITIES FIXED:
{vulnerability_summary}

CODE CHANGES:
{code_fix}

COMPLIANCE REQUIREMENTS:
{compliance_requirements}

Generate a professional PR description with:
- Title (concise, starts with [SECURITY])
- Summary
- Changes Made
- Security Impact
- Compliance Status
- Testing Done
- Checklist for reviewers
"""

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": "You are a technical writer creating security PR descriptions."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.4,
        max_tokens=1500
    )
    
    return response.choices[0].message.content
