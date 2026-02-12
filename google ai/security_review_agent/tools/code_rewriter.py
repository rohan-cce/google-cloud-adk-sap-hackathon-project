# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tool to rewrite vulnerable code into secure versions.

The heavy lifting (understanding the vulnerability and producing the fix)
is done by the Gemini model via the agent's LLM. This tool provides the
structured interface for the agent to call and return results.
"""


def rewrite_secure_code(code: str, vulnerabilities: str) -> dict:
    """Produce a secure rewrite of vulnerable code based on detected vulnerabilities.

    This tool is called by the agent after vulnerabilities have been detected.
    The agent (Gemini) uses its understanding of the vulnerabilities to produce
    the actual secure rewrite. This function provides the structured interface.

    Args:
        code: The original vulnerable source code.
        vulnerabilities: A JSON string describing the detected vulnerabilities
                        (type, CWE, severity, line, description).

    Returns:
        dict: A dictionary with the secure rewrite and a summary of changes made.
    """
    if not code or not code.strip():
        return {
            "status": "error",
            "error_message": "No code provided to rewrite.",
        }

    if not vulnerabilities or not vulnerabilities.strip():
        return {
            "status": "success",
            "message": "No vulnerabilities provided — code appears clean.",
            "secure_code": code,
            "changes": [],
        }

    # The agent's LLM will analyze the code and vulnerabilities,
    # then produce the secure rewrite. This tool returns the structure
    # that the agent populates with the actual fix.
    return {
        "status": "ready",
        "message": (
            "Analyze the provided code and vulnerabilities. "
            "Produce a complete, secure rewrite that:\n"
            "1. Fixes ALL identified vulnerabilities\n"
            "2. Uses parameterized queries instead of string concatenation for SQL\n"
            "3. Replaces hardcoded credentials with os.environ / environment variables\n"
            "4. Replaces eval()/exec() with safe alternatives (ast.literal_eval, json.loads)\n"
            "5. Replaces weak hashing (MD5/SHA1) with bcrypt/argon2/SHA-256\n"
            "6. Sanitizes file paths and user inputs\n"
            "7. Uses textContent instead of innerHTML for DOM manipulation\n"
            "8. Preserves original functionality\n"
            "9. Includes any new imports needed\n"
            "10. Is syntactically valid and runnable"
        ),
        "original_code": code,
        "vulnerabilities_to_fix": vulnerabilities,
    }
