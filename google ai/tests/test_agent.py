# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tests for the ADK agent tools."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")


class TestCodeValidator(unittest.TestCase):
    """Test the code validator tool."""

    def test_valid_python(self):
        from security_review_agent.tools.code_validator import validate_code
        code = "x = 1\nprint(x)"
        result = validate_code(code, "python")
        self.assertTrue(result.get("valid", False))

    def test_invalid_python(self):
        from security_review_agent.tools.code_validator import validate_code
        code = "def foo(\n  x = "  # Invalid syntax
        result = validate_code(code, "python")
        self.assertFalse(result.get("valid", True))

    def test_empty_code(self):
        from security_review_agent.tools.code_validator import validate_code
        result = validate_code("", "python")
        self.assertEqual(result["status"], "error")

    def test_unknown_language(self):
        from security_review_agent.tools.code_validator import validate_code
        result = validate_code("some code", "cobol")
        self.assertTrue(result.get("valid", False))  # Skips validation


class TestCodeRewriter(unittest.TestCase):
    """Test the code rewriter tool interface."""

    def test_empty_code(self):
        from security_review_agent.tools.code_rewriter import rewrite_secure_code
        result = rewrite_secure_code("", "some vulns")
        self.assertEqual(result["status"], "error")

    def test_no_vulnerabilities(self):
        from security_review_agent.tools.code_rewriter import rewrite_secure_code
        result = rewrite_secure_code("x = 1", "")
        self.assertEqual(result["status"], "success")

    def test_ready_for_rewrite(self):
        from security_review_agent.tools.code_rewriter import rewrite_secure_code
        result = rewrite_secure_code("password = '123'", '[{"type": "Hardcoded Credentials"}]')
        self.assertEqual(result["status"], "ready")


class TestPatchAnalysis(unittest.TestCase):
    """Test analyzing the sample patch file end-to-end."""

    def test_sample_patch(self):
        from security_review_agent.tools.code_analyzer import analyze_code_diff
        from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities

        patch_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sample_prs",
            "sample_diff.patch",
        )

        if not os.path.exists(patch_path):
            self.skipTest("sample_diff.patch not found")

        with open(patch_path, "r") as f:
            diff = f.read()

        # Parse the diff
        analysis = analyze_code_diff(diff)
        self.assertEqual(analysis["status"], "success")
        self.assertTrue(len(analysis["files"]) >= 2)

        # Scan for vulnerabilities
        total_vulns = 0
        for file_info in analysis["files"]:
            result = detect_vulnerabilities(
                code=file_info["added_code"],
                filename=file_info["filename"],
            )
            total_vulns += len(result.get("vulnerabilities", []))

        # We expect at least several vulnerabilities in the sample
        self.assertGreater(total_vulns, 5, "Expected at least 5 vulnerabilities in sample files")


if __name__ == "__main__":
    unittest.main()
