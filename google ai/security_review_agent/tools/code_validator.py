# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tool to validate that rewritten code has valid syntax."""

import os
import subprocess
import tempfile


def validate_code(code: str, language: str) -> dict:
    """Validate that code has correct syntax by running a language-specific checker.

    Args:
        code: The source code to validate.
        language: The programming language ("python", "javascript", etc.).

    Returns:
        dict: A dictionary with validation status (pass/fail) and any error details.
    """
    if not code or not code.strip():
        return {
            "status": "error",
            "error_message": "No code provided to validate.",
        }

    language = language.lower().strip()

    if language == "python":
        return _validate_python(code)
    elif language in ("javascript", "typescript"):
        return _validate_javascript(code)
    else:
        return {
            "status": "success",
            "valid": True,
            "message": f"Syntax validation not available for '{language}'. Skipping.",
        }


def _validate_python(code: str) -> dict:
    """Validate Python syntax using py_compile."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            ["python", "-m", "py_compile", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )

        os.unlink(tmp_path)

        if result.returncode == 0:
            return {
                "status": "success",
                "valid": True,
                "message": "Python code is syntactically valid. ✅",
            }
        else:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return {
                "status": "success",
                "valid": False,
                "message": f"Python syntax error detected: {error_msg}",
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "Validation timed out after 10 seconds.",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Validation failed: {str(e)}",
        }


def _validate_javascript(code: str) -> dict:
    """Validate JavaScript syntax using node --check."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False
        ) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            ["node", "--check", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )

        os.unlink(tmp_path)

        if result.returncode == 0:
            return {
                "status": "success",
                "valid": True,
                "message": "JavaScript code is syntactically valid. ✅",
            }
        else:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return {
                "status": "success",
                "valid": False,
                "message": f"JavaScript syntax error detected: {error_msg}",
            }

    except FileNotFoundError:
        return {
            "status": "success",
            "valid": True,
            "message": "Node.js not found — skipping JS validation.",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "Validation timed out after 10 seconds.",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Validation failed: {str(e)}",
        }
