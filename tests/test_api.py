"""
Tests for the Security Orchestrator Bot API endpoints.
Run with: pytest tests/ -v
"""
import os
import sys
import json
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock


# ==========================================
# Test Scanner Tool (no external deps needed)
# ==========================================
class TestScannerTool:
    """Tests for the scanner_tool module."""

    def test_detect_language_python(self, tmp_path):
        """Test language detection for Python projects."""
        from app.mcp_servers.scanner_tool import detect_language
        # Create some Python files
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("x = 1")
        (tmp_path / "test.py").write_text("assert True")
        result = detect_language(str(tmp_path))
        assert result == "python"

    def test_detect_language_javascript(self, tmp_path):
        """Test language detection for JavaScript projects."""
        from app.mcp_servers.scanner_tool import detect_language
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "app.js").write_text("const x = 1")
        (tmp_path / "server.js").write_text("http.listen(3000)")
        result = detect_language(str(tmp_path))
        assert result == "javascript"

    def test_detect_language_empty_dir(self, tmp_path):
        """Test language detection for empty directory."""
        from app.mcp_servers.scanner_tool import detect_language
        result = detect_language(str(tmp_path))
        assert result == "auto"

    def test_detect_language_mixed(self, tmp_path):
        """Test language detection for mixed-language project."""
        from app.mcp_servers.scanner_tool import detect_language
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "main.py").write_text("x = 1")
        result = detect_language(str(tmp_path))
        assert result == "python"  # More .py files

    def test_normalize_severity(self):
        """Test severity normalization."""
        from app.mcp_servers.scanner_tool import _normalize_severity
        assert _normalize_severity("ERROR") == "HIGH"
        assert _normalize_severity("WARNING") == "MEDIUM"
        assert _normalize_severity("INFO") == "LOW"
        assert _normalize_severity("CRITICAL") == "CRITICAL"
        assert _normalize_severity("unknown") == "MEDIUM"

    def test_run_scan_unknown_tool(self, tmp_path):
        """Test running scan with unknown tool name."""
        from app.mcp_servers.scanner_tool import run_security_scan
        result = run_security_scan(str(tmp_path), "unknown-tool")
        assert result == []


# ==========================================
# Test Helper Functions (main.py)
# ==========================================
class TestHelperFunctions:
    """Tests for main.py helper functions."""

    def test_sanitize_filename_valid(self):
        """Test sanitize_filename with valid filenames."""
        from app.main import sanitize_filename
        assert sanitize_filename("report_2024.json") == "report_2024.json"
        assert sanitize_filename("test-file.json") == "test-file.json"

    def test_sanitize_filename_path_traversal(self):
        """Test sanitize_filename blocks path traversal."""
        from app.main import sanitize_filename
        # Path traversal attempts
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("..\\..\\windows\\system32") == "system32"

    def test_sanitize_filename_hidden_file(self):
        """Test sanitize_filename blocks hidden files."""
        from app.main import sanitize_filename
        with pytest.raises(ValueError):
            sanitize_filename(".hidden")

    def test_sanitize_filename_empty(self):
        """Test sanitize_filename blocks empty filenames."""
        from app.main import sanitize_filename
        with pytest.raises(ValueError):
            sanitize_filename("")

    def test_extract_pr_details_with_security_tag(self):
        """Test extracting PR title with [SECURITY] tag."""
        from app.main import extract_pr_details
        ai_text = "Here is the fix.\n[SECURITY] Fix SQL injection in auth.py\nMore details..."
        title, body = extract_pr_details(ai_text)
        assert "[SECURITY]" in title
        assert body == ai_text

    def test_extract_pr_details_fallback(self):
        """Test extracting PR title without [SECURITY] tag."""
        from app.main import extract_pr_details
        ai_text = "Title: Fix login vulnerability\nBody text here"
        title, body = extract_pr_details(ai_text)
        assert "Fix login vulnerability" in title

    def test_extract_pr_details_no_match(self):
        """Test extracting PR title with no recognizable pattern."""
        from app.main import extract_pr_details
        ai_text = "Some analysis without a clear title"
        title, body = extract_pr_details(ai_text)
        assert "[SECURITY]" in title  # Falls back to default

    def test_extract_code_fix_python(self):
        """Test extracting Python code block."""
        from app.main import extract_code_fix
        ai_text = "Here is the fix:\n```python\nimport os\nprint('secure')\n```\nDone."
        code = extract_code_fix(ai_text)
        assert code == "import os\nprint('secure')"

    def test_extract_code_fix_javascript(self):
        """Test extracting JavaScript code block."""
        from app.main import extract_code_fix
        ai_text = "Fix:\n```javascript\nconst x = sanitize(input);\n```"
        code = extract_code_fix(ai_text)
        assert "sanitize" in code

    def test_extract_code_fix_no_code(self):
        """Test when no code block is present."""
        from app.main import extract_code_fix
        ai_text = "No code block here, just text analysis."
        code = extract_code_fix(ai_text)
        assert code is None


# ==========================================
# Test GitHub Integration
# ==========================================
class TestGitHubIntegration:
    """Tests for GitHub integration functions."""

    @patch("app.github_integration.requests.post")
    def test_create_pr_success(self, mock_post):
        """Test successful PR creation."""
        from app.github_integration import create_github_pr
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"html_url": "https://github.com/owner/repo/pull/1"},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        with patch.dict(os.environ, {"GITHUB_TOKEN": "fake-token"}):
            result = create_github_pr("owner", "repo", "fix/branch", "Title", "Body")
            assert result == "https://github.com/owner/repo/pull/1"

    @patch("app.github_integration.GITHUB_TOKEN", None)
    def test_create_pr_no_token(self):
        """Test PR creation without GITHUB_TOKEN."""
        from app.github_integration import create_github_pr
        result = create_github_pr("owner", "repo", "fix/branch", "Title", "Body")
        assert result is None

    @patch("app.github_integration.GITHUB_TOKEN", None)
    def test_push_file_no_token(self):
        """Test push_file_update without GITHUB_TOKEN."""
        from app.github_integration import push_file_update
        result = push_file_update("owner", "repo", "branch", "main", "file.py", "code", "msg")
        assert result is False


# ==========================================
# Test Data Models
# ==========================================
class TestDataModels:
    """Tests for Pydantic data models."""

    def test_security_finding_minimal(self):
        """Test SecurityFinding with minimal data."""
        from app.main import SecurityFinding
        finding = SecurityFinding(vulnerability="SQL Injection")
        assert finding.vulnerability == "SQL Injection"
        assert finding.code is None
        assert finding.file is None

    def test_security_finding_full(self):
        """Test SecurityFinding with all fields."""
        from app.main import SecurityFinding
        finding = SecurityFinding(
            vulnerability="XSS",
            code="<script>alert(1)</script>",
            file="app/views.py",
            line=42,
            severity="HIGH",
        )
        assert finding.line == 42
        assert finding.severity == "HIGH"

    def test_tool_report(self):
        """Test ToolReport model."""
        from app.main import ToolReport, SecurityFinding
        report = ToolReport(
            tool="bandit",
            findings=SecurityFinding(vulnerability="Hardcoded password"),
        )
        assert report.tool == "bandit"

    def test_jenkins_payload_defaults(self):
        """Test JenkinsPayload default values."""
        from app.main import JenkinsPayload, BuildInfo, ToolReport, SecurityFinding
        payload = JenkinsPayload(
            name="test",
            build=BuildInfo(full_url="http://test", log="test log"),
            job_name="test-job",
            build_url="http://test/1",
            reports=[
                ToolReport(tool="bandit", findings=SecurityFinding(vulnerability="test"))
            ],
        )
        assert payload.branch == "main"
        assert payload.job_name == "test-job"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
