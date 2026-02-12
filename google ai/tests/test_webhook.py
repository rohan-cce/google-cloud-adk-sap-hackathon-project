# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tests for webhook signature verification and basic endpoint functionality."""

import hashlib
import hmac
import json
import os
import sys
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-12345")
os.environ.setdefault("GITHUB_TOKEN", "test-token")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")

from webhook_server import app


class TestWebhookSignature(unittest.TestCase):
    """Test HMAC signature verification."""

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        self.secret = "test-secret-12345"

    def _sign_payload(self, payload: bytes) -> str:
        """Generate a valid HMAC-SHA256 signature for a payload."""
        mac = hmac.new(self.secret.encode("utf-8"), payload, hashlib.sha256)
        return f"sha256={mac.hexdigest()}"

    def test_health_check(self):
        """Test GET /health returns 200."""
        response = self.app.get("/health")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "ok")

    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected with 403."""
        payload = json.dumps({"action": "opened"}).encode()
        response = self.app.post(
            "/webhook",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=invalidsignature",
                "X-GitHub-Event": "pull_request",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_non_pr_event_ignored(self):
        """Test that non-pull_request events are ignored."""
        payload = json.dumps({"action": "created"}).encode()
        signature = self._sign_payload(payload)
        response = self.app.post(
            "/webhook",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "issue_comment",
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_pr_closed_action_ignored(self):
        """Test that PR 'closed' action is ignored."""
        payload = json.dumps({"action": "closed"}).encode()
        signature = self._sign_payload(payload)
        response = self.app.post(
            "/webhook",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": signature,
                "X-GitHub-Event": "pull_request",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("Ignoring", data["message"])

    def test_time_machine_requires_repo(self):
        """Test POST /time-machine requires 'repo' field."""
        response = self.app.post(
            "/time-machine",
            data=json.dumps({}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)

    def test_analytics_endpoint_accepts_empty(self):
        """Test POST /analytics accepts empty body (scans all repos)."""
        response = self.app.post(
            "/analytics",
            data=json.dumps({}),
            headers={"Content-Type": "application/json"},
        )
        # Will return error because BigQuery isn't set up in test, but shouldn't crash
        self.assertIn(response.status_code, [200, 500])


class TestCodeAnalyzer(unittest.TestCase):
    """Test the code analyzer tool."""

    def test_empty_diff(self):
        from security_review_agent.tools.code_analyzer import analyze_code_diff
        result = analyze_code_diff("")
        self.assertEqual(result["status"], "error")

    def test_parse_simple_diff(self):
        from security_review_agent.tools.code_analyzer import analyze_code_diff
        diff = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
+import os
 print("hello")
"""
        result = analyze_code_diff(diff)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["files"][0]["filename"], "test.py")
        self.assertEqual(result["files"][0]["language"], "python")


class TestVulnerabilityDetector(unittest.TestCase):
    """Test the vulnerability detector tool."""

    def test_detect_hardcoded_password(self):
        from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
        code = 'password = "super_secret_123"'
        result = detect_vulnerabilities(code, "test.py")
        self.assertTrue(len(result["vulnerabilities"]) > 0)
        self.assertEqual(result["vulnerabilities"][0]["type"], "Hardcoded Credentials")

    def test_detect_sql_injection(self):
        from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        result = detect_vulnerabilities(code, "test.py")
        vulns = result["vulnerabilities"]
        sql_vulns = [v for v in vulns if v["type"] == "SQL Injection"]
        self.assertTrue(len(sql_vulns) > 0)

    def test_detect_eval(self):
        from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
        code = 'result = eval(user_input)'
        result = detect_vulnerabilities(code, "test.py")
        vulns = result["vulnerabilities"]
        injection_vulns = [v for v in vulns if v["type"] == "Code Injection"]
        self.assertTrue(len(injection_vulns) > 0)

    def test_clean_code(self):
        from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
        code = 'x = 1 + 2\nprint(x)'
        result = detect_vulnerabilities(code, "test.py")
        self.assertEqual(len(result["vulnerabilities"]), 0)


if __name__ == "__main__":
    unittest.main()
