# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Flask webhook server for receiving GitHub PR events and invoking the Security Review Agent."""

import hashlib
import hmac
import json
import logging
import os
import traceback

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request

from security_review_agent.agent import root_agent
from security_review_agent.shared_libraries import constants
from security_review_agent.tools.code_analyzer import analyze_code_diff
from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
from security_review_agent.tools.code_rewriter import rewrite_secure_code
from security_review_agent.tools.code_validator import validate_code
from security_review_agent.tools.bigquery_logger import log_to_bigquery
from security_review_agent.tools.gcs_uploader import upload_to_gcs
from security_review_agent.tools.security_time_machine import query_security_history
from security_review_agent.tools.vulnerability_analytics import get_top_vulnerabilities

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Health Check ────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Cloud Run health check endpoint."""
    return jsonify({"status": "ok", "agent": constants.AGENT_NAME, "roast_mode": constants.ROAST_MODE}), 200


# ─── GitHub Webhook ──────────────────────────────────────────────────────────

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    """Handle GitHub webhook events for pull requests."""
    # 1. Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(request.data, signature):
        logger.warning("Invalid webhook signature received.")
        return jsonify({"error": "Invalid signature"}), 403

    # 2. Parse event
    event = request.headers.get("X-GitHub-Event", "")
    payload = request.json

    if event != "pull_request":
        return jsonify({"message": f"Ignoring event: {event}"}), 200

    action = payload.get("action", "")
    if action not in ("opened", "synchronize"):
        return jsonify({"message": f"Ignoring PR action: {action}"}), 200

    # 3. Extract PR details
    pr = payload["pull_request"]
    repo_full = payload["repository"]["full_name"]
    pr_number = pr["number"]
    pr_author = pr["user"]["login"]
    pr_title = pr["title"]

    logger.info(f"Processing PR #{pr_number} '{pr_title}' on {repo_full} by {pr_author}")

    try:
        # 4. Fetch the PR diff from GitHub
        diff = _fetch_pr_diff(repo_full, pr_number)
        if not diff:
            return jsonify({"message": "Could not fetch PR diff"}), 500

        # 5. Run security analysis pipeline
        result = _run_security_analysis(diff, repo_full, pr_number, pr_author)

        # 6. Post PR review with inline suggestions
        _post_review_with_suggestions(
            repo_full, pr_number, result["review_body"], result["inline_comments"]
        )

        return jsonify({
            "message": "Security review completed",
            "pr": f"{repo_full}#{pr_number}",
            "vulnerabilities_found": result["vulnerabilities_found"],
            "inline_suggestions": len(result["inline_comments"]),
        }), 202

    except Exception as e:
        logger.error(f"Error processing PR: {e}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


# ─── Security Time Machine Endpoint ─────────────────────────────────────────

@app.route("/time-machine", methods=["POST"])
def time_machine():
    """Query historical security scan trends for a repository."""
    data = request.json or {}
    repo = data.get("repo", "")
    num_prs = data.get("num_prs", 10)

    if not repo:
        return jsonify({"error": "Missing 'repo' field"}), 400

    result = query_security_history(repo=repo, num_prs=num_prs)
    return jsonify(result), 200


# ─── Top Vulnerability Analytics Endpoint ────────────────────────────────────

@app.route("/analytics", methods=["POST"])
def analytics():
    """Get top vulnerability type breakdown across scans."""
    data = request.json or {}
    repo = data.get("repo", None)
    limit = data.get("limit", 10)

    result = get_top_vulnerabilities(repo=repo, limit=limit)
    return jsonify(result), 200


# ─── Internal Helpers ────────────────────────────────────────────────────────

def _verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify the GitHub webhook HMAC-SHA256 signature."""
    secret = constants.GITHUB_WEBHOOK_SECRET
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not set — skipping signature verification.")
        return True  # Allow in dev mode

    if not signature_header:
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature_header)


def _fetch_pr_diff(repo_full: str, pr_number: int) -> str:
    """Fetch the unified diff for a pull request from GitHub API."""
    url = f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}"
    headers = {
        "Authorization": f"token {constants.GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }

    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code == 200:
        return response.text
    else:
        logger.error(f"Failed to fetch diff: {response.status_code} {response.text}")
        return ""


def _run_security_analysis(
    diff: str, repo: str, pr_number: int, pr_author: str
) -> dict:
    """Run the full security analysis pipeline on a PR diff."""

    # Step 1: Analyze the diff
    analysis = analyze_code_diff(diff)
    files = analysis.get("files", [])

    if not files:
        return {
            "vulnerabilities_found": 0,
            "review_body": "✅ **Security Review**: No code changes detected in this PR.",
            "inline_comments": [],
        }

    # Step 2: Detect vulnerabilities in each file
    all_vulnerabilities = []
    for file_info in files:
        result = detect_vulnerabilities(
            code=file_info["added_code"],
            filename=file_info["filename"],
        )
        vulns = result.get("vulnerabilities", [])
        line_map = file_info.get("line_map", {})

        for v in vulns:
            v["filename"] = file_info["filename"]
            # Map added-code line number → actual file line number
            v["file_line"] = line_map.get(v["line"], v["line"])

        all_vulnerabilities.extend(vulns)

    # Step 3: Generate review body (summary comment)
    if not all_vulnerabilities:
        review_body = "✅ **Security Review**: No vulnerabilities detected. Clean code! 🎉"
    else:
        review_body = _format_review_summary(all_vulnerabilities)

    # Step 4: Build inline suggestion comments for the PR Review
    inline_comments = _build_inline_comments(all_vulnerabilities)

    # Step 5: Upload artifacts to GCS
    diff_blob = f"scans/{repo.replace('/', '-')}/pr-{pr_number}/diff.patch"
    upload_to_gcs(diff, diff_blob)

    if all_vulnerabilities:
        vuln_blob = f"scans/{repo.replace('/', '-')}/pr-{pr_number}/vulnerabilities.json"
        upload_to_gcs(json.dumps(all_vulnerabilities, indent=2), vuln_blob)

    # Step 6: Log to BigQuery
    vuln_types = list(set(v["type"] for v in all_vulnerabilities))
    severity_counts = {}
    for v in all_vulnerabilities:
        sev = v.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    bq_result = log_to_bigquery({
        "repo": repo,
        "pr_number": pr_number,
        "pr_author": pr_author,
        "vulnerabilities_found": len(all_vulnerabilities),
        "vulnerability_types": ",".join(vuln_types),
        "severity_summary": json.dumps(severity_counts),
        "status": "clean" if not all_vulnerabilities else "vulnerabilities_found",
        "diff_gcs_uri": f"gs://{constants.GCS_BUCKET_NAME}/{diff_blob}",
        "remediation_gcs_uri": "",
        "roast_mode": constants.ROAST_MODE,
    })

    if bq_result.get("status") == "error":
        logger.error(f"BigQuery logging failed: {bq_result.get('error_message')}")
    else:
        logger.info(f"BigQuery logging success: {bq_result.get('message')}")

    return {
        "vulnerabilities_found": len(all_vulnerabilities),
        "review_body": review_body,
        "inline_comments": inline_comments,
    }


def _format_review_summary(vulnerabilities: list) -> str:
    """Format a summary of the security review (goes in the review body, not inline)."""
    severity_counts = {}
    for v in vulnerabilities:
        sev = v.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    severity_str = ", ".join(f"{count} {sev}" for sev, count in sorted(severity_counts.items()))

    if constants.ROAST_MODE:
        body = f"🔥 **Security Roast Review** — Found {len(vulnerabilities)} issue(s): {severity_str}\n\n"
        body += "_Buckle up, this is going to hurt._\n\n"
    else:
        body = f"🛡️ **Security Review** — Found {len(vulnerabilities)} vulnerability(ies): {severity_str}\n\n"

    body += "Each finding has an **inline suggestion** that you can apply with one click.\n\n"

    # Quick summary table
    body += "| # | Type | Severity | File | Line |\n"
    body += "|---|------|----------|------|------|\n"
    for i, v in enumerate(vulnerabilities, 1):
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v["severity"], "⚪")
        body += f"| {i} | {emoji} {v['type']} | {v['severity']} | `{v.get('filename', '?')}` | {v.get('file_line', v['line'])} |\n"

    body += "\n---\n\n"

    if constants.ROAST_MODE:
        body += "💡 **Redemption Arc**: Apply the suggestions and you'll earn back my respect. Maybe. 🔥\n"
    else:
        body += "💡 **Recommendation**: Click **Apply suggestion** on each finding to fix the vulnerability inline.\n"

    return body


def _build_inline_comments(vulnerabilities: list) -> list:
    """Build GitHub PR Review inline comments with suggestion blocks."""

    # 🔥 Roast commentary per vulnerability type
    roast_map = {
        "Hardcoded Credentials": [
            "Storing secrets in source code? Bold strategy. Let's see if it pays off. (Spoiler: it won't.)",
            "I've seen better secret management from a kid's diary with a dollar-store lock. 🔓",
            "Congratulations, you just open-sourced your credentials. The whole internet thanks you. 👏",
            "Did you just… commit your API key? In 2026? We have env vars, you know.",
            "This secret is more exposed than a celebrity's leaked photos. Please use a secret manager.",
        ],
        "SQL Injection": [
            "Ah yes, concatenated SQL — the hacker's favorite snack. 🍿",
            "Bobby Tables called — he'd like a word with you.",
            "This query is so injectable, it should come with a syringe emoji. 💉",
            "You basically left the front door open AND put up a 'Free Data' sign.",
        ],
        "Code Injection": [
            "Using eval() on user input is like handing a stranger your house keys. 🏠",
            "eval() on untrusted data? That's not a feature, that's a remote code execution buffet. 🍽️",
            "Oh cool, a free RCE endpoint. Very generous of you.",
            "This eval() is so dangerous it should require safety goggles. 🥽",
        ],
        "Weak Cryptography": [
            "MD5 for password hashing? What year is this, 2003? ⏰",
            "Using MD5 is like locking your front door with scotch tape. 🔒",
            "SHA1? Even Git is moving away from it, and Git doesn't even use it for security.",
            "This hash is weaker than gas station coffee. ☕",
        ],
        "Cross-Site Scripting (XSS)": [
            "innerHTML with user data? That's launching a XSS attack on your own users. 🎯",
            "document.write()? What is this, a GeoCities page from 1999?",
            "You're basically letting users rewrite your UI. That's democracy, but not the good kind.",
        ],
        "Path Traversal": [
            "No path sanitization? Attackers are about to tour your entire filesystem. 🗺️",
            "../../etc/passwd says hello. And so does your entire server.",
        ],
    }

    comments = []
    for i, v in enumerate(vulnerabilities):
        filename = v.get("filename", "")
        file_line = v.get("file_line", v.get("line", 0))
        suggestion = v.get("secure_suggestion", "")
        span_lines = v.get("span_lines", 1)

        if not filename or not file_line:
            continue

        # Build the comment body with a GitHub suggestion block
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v["severity"], "⚪")
        body = f"{emoji} **{v['type']}** ({v['cwe']}) — Severity: **{v['severity']}**\n\n"
        body += f"{v['description']}\n\n"

        # 🔥 Add roast commentary if enabled
        if constants.ROAST_MODE:
            roasts = roast_map.get(v["type"], [])
            if roasts:
                roast = roasts[i % len(roasts)]
                body += f"🔥 _{roast}_\n\n"

        # ⚠️ Show required imports
        required_import = v.get("required_import")
        if required_import:
            body += f"⚠️ **Required import** — add this at the top of your file:\n```python\n{required_import}\n```\n\n"

        if suggestion:
            body += f"```suggestion\n{suggestion}\n```\n"

        comment = {
            "path": filename,
            "line": file_line,
            "body": body,
        }

        # Multi-line suggestion: use start_line + line to span multiple lines
        if span_lines > 1:
            end_file_line = v.get("file_end_line", file_line + span_lines - 1)
            comment["start_line"] = file_line
            comment["line"] = end_file_line

        comments.append(comment)

    return comments


def _post_review_with_suggestions(
    repo_full: str, pr_number: int, review_body: str, inline_comments: list
):
    """Post a PR Review with inline suggestion comments using the GitHub PR Reviews API.

    This uses the `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews` endpoint
    which supports inline comments with ```suggestion blocks that developers can
    one-click apply.

    Falls back to a regular issue comment if the review API fails.
    """
    url = f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {constants.GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Determine review event: REQUEST_CHANGES if vulns found, APPROVE if clean
    event = "REQUEST_CHANGES" if inline_comments else "APPROVE"

    payload = {
        "body": review_body,
        "event": event,
        "comments": inline_comments,
    }

    response = requests.post(url, headers=headers, json=payload, timeout=60)

    if response.status_code in (200, 201):
        logger.info(
            f"Posted PR review on {repo_full}#{pr_number} with "
            f"{len(inline_comments)} inline suggestion(s)"
        )
    elif response.status_code == 422:
        # Validation error — usually "pull_request_review_thread.line must be part of the diff"
        # This happens when line numbers don't map perfectly to the diff.
        # Fall back to posting inline comments one-by-one, skipping failures.
        logger.warning(
            f"Bulk review failed (422), falling back to individual comments. "
            f"Error: {response.text}"
        )
        _post_review_fallback(repo_full, pr_number, review_body, inline_comments)
    else:
        logger.error(f"Failed to post review: {response.status_code} {response.text}")
        # Fall back to a simple issue comment
        _post_issue_comment(repo_full, pr_number, review_body)


def _post_review_fallback(
    repo_full: str, pr_number: int, review_body: str, inline_comments: list
):
    """Fallback: post summary as issue comment + individual review comments."""
    # Post summary as a regular issue comment
    _post_issue_comment(repo_full, pr_number, review_body)

    # Try posting each inline comment as individual single-comment reviews
    for comment in inline_comments:
        url = f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/reviews"
        headers = {
            "Authorization": f"token {constants.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        }
        payload = {
            "body": "",
            "event": "COMMENT",
            "comments": [comment],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code not in (200, 201):
            logger.warning(
                f"Could not post inline comment for {comment['path']}:{comment['line']} — "
                f"{resp.status_code}"
            )


def _post_issue_comment(repo_full: str, pr_number: int, body: str):
    """Fallback: post a regular issue comment (no inline suggestions)."""
    url = f"https://api.github.com/repos/{repo_full}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {constants.GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.post(url, headers=headers, json={"body": body}, timeout=30)

    if response.status_code in (200, 201):
        logger.info(f"Posted issue comment on {repo_full}#{pr_number}")
    else:
        logger.error(f"Failed to post comment: {response.status_code} {response.text}")


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info(f"Starting webhook server on port {constants.PORT}")
    logger.info(f"Roast mode: {'🔥 ON' if constants.ROAST_MODE else 'OFF'}")
    app.run(host="0.0.0.0", port=constants.PORT, debug=True)
