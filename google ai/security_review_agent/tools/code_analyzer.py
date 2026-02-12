# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tool to parse unified diffs and extract changed code from pull requests."""

import re


def analyze_code_diff(diff: str) -> dict:
    """Parse a unified-diff string and extract changed files with their added code.

    Args:
        diff: A unified-diff string (as returned by GitHub's PR diff API).

    Returns:
        dict: A dictionary with status and a list of changed files, each containing
              the filename, language, added lines of code, and a line_map that maps
              added-code line numbers (1-indexed) to actual file line numbers.
    """
    if not diff or not diff.strip():
        return {
            "status": "error",
            "error_message": "Empty diff provided. No code changes to analyze.",
        }

    files = []
    current_file = None
    current_lines = []
    # Maps: added-code line index (1-based) → actual file line number
    current_line_map = {}
    # Current position in the target file (from @@ hunk headers)
    file_line = 0

    for line in diff.split("\n"):
        # Detect new file in diff
        if line.startswith("diff --git"):
            # Save previous file if exists
            if current_file and current_lines:
                files.append({
                    "filename": current_file,
                    "language": _detect_language(current_file),
                    "added_code": "\n".join(current_lines),
                    "line_map": dict(current_line_map),
                })
            # Extract filename from diff header
            match = re.search(r"b/(.+)$", line)
            current_file = match.group(1) if match else "unknown"
            current_lines = []
            current_line_map = {}
            file_line = 0

        # Parse @@ hunk header to get actual file line numbers
        # Format: @@ -old_start,old_count +new_start,new_count @@
        elif line.startswith("@@"):
            hunk_match = re.search(r"\+(\d+)", line)
            if hunk_match:
                file_line = int(hunk_match.group(1))

        # Collect added lines (lines starting with +, but not +++ header)
        elif line.startswith("+") and not line.startswith("+++"):
            current_lines.append(line[1:])  # Remove the leading +
            added_line_num = len(current_lines)  # 1-based index in added_code
            current_line_map[added_line_num] = file_line
            file_line += 1

        # Context lines (unchanged) — advance file line counter
        elif not line.startswith("-") and not line.startswith("---"):
            file_line += 1

        # Deleted lines don't advance the new-file line counter

    # Don't forget the last file
    if current_file and current_lines:
        files.append({
            "filename": current_file,
            "language": _detect_language(current_file),
            "added_code": "\n".join(current_lines),
            "line_map": dict(current_line_map),
        })

    if not files:
        return {
            "status": "success",
            "message": "No added code found in the diff.",
            "files": [],
        }

    return {
        "status": "success",
        "message": f"Found {len(files)} file(s) with code changes.",
        "files": files,
    }


def _detect_language(filename: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".rs": "rust",
        ".swift": "swift",
        ".kt": "kotlin",
        ".sql": "sql",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
    }
    for ext, lang in ext_map.items():
        if filename.endswith(ext):
            return lang
    return "unknown"
