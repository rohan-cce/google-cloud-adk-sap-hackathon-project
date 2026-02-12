# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Local simulation script — test the Security Review Agent without GitHub.

Usage:
    python simulate_pr.py --patch sample_prs/sample_diff.patch
    python simulate_pr.py --patch sample_prs/sample_diff.patch --roast
    python simulate_pr.py --file sample_prs/vulnerable_python.py
"""

import argparse
import json
import os
import random
import sys

from dotenv import load_dotenv

# Load environment before importing agent modules
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "security_review_agent", ".env"))

from security_review_agent.tools.code_analyzer import analyze_code_diff
from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities
from security_review_agent.tools.code_validator import validate_code

# ─── Roast Commentary Map ────────────────────────────────────────────────────
# Multiple roasts per vulnerability type for variety

ROAST_MAP = {
    "Hardcoded Credentials": [
        "Storing passwords in source code? Bold strategy. Let's see if it pays off. (Spoiler: it won't.)",
        "I've seen better secret management from a kid's diary with a dollar-store lock. 🔓",
        "Congratulations, you just open-sourced your credentials. The whole internet thanks you. 👏",
        "This secret is more exposed than a celebrity's leaked photos. Please use env vars.",
        "Did you just… commit your API key? In 2026? We have environment variables, you know.",
    ],
    "SQL Injection": [
        "Ah yes, concatenated SQL — the hacker's favorite snack. 🍿",
        "String concatenation in SQL? Bobby Tables called — he'd like a word with you.",
        "This query is so injectable, it should come with a syringe emoji. 💉",
        "You basically left the front door open AND put up a 'Free Data' sign.",
        "I haven't seen SQL this exploitable since… well, since the last PR I reviewed.",
    ],
    "Code Injection": [
        "Using eval() on user input is like handing a stranger your house keys and asking them to 'just look around.' 🏠",
        "eval() on untrusted data? That's not a feature, that's a remote code execution buffet. 🍽️",
        "Oh cool, a free RCE endpoint. Very generous of you.",
        "exec() on user input? Why not just give attackers SSH access? Same energy.",
        "This eval() is so dangerous it should require safety goggles. 🥽",
    ],
    "Weak Cryptography": [
        "MD5 for password hashing? What year is this, 2003? ⏰",
        "Using MD5 is like locking your front door with scotch tape. 🔒",
        "SHA1? Even Git is moving away from it, and Git doesn't even use it for security.",
        "This hash is weaker than gas station coffee. ☕",
        "MD5 was broken before some junior devs were born. Upgrade to bcrypt, please.",
    ],
    "Cross-Site Scripting (XSS)": [
        "innerHTML with user data? That's not rendering HTML, that's launching a XSS attack on your own users. 🎯",
        "document.write()? What is this, a GeoCities page from 1999?",
        "You're basically letting users rewrite your UI. That's democracy, but not the good kind.",
        "This XSS is so textbook, it's literally in every security textbook. 📚",
    ],
    "Path Traversal": [
        "No path sanitization? Attackers are about to take a grand tour of your entire filesystem. 🗺️",
        "../../etc/passwd says hello. And so does your entire server.",
        "This file read is so open, it's basically a public library. 📖",
    ],
}

ROAST_SUMMARY_INTROS = [
    "Found {n} security disasters in this PR. Let's talk about your life choices.",
    "Wow. Just… wow. {n} vulnerabilities. Did you write this code blindfolded?",
    "{n} findings. This PR is a security researcher's dream and a CISO's nightmare.",
    "I found {n} vulnerabilities. My disappointment is immeasurable, and my day is ruined.",
    "This code has {n} security holes. Swiss cheese called — it wants its identity back. 🧀",
]

ROAST_CLOSERS = [
    "💡 Redemption Arc: Fix these issues and you'll earn back my respect. Maybe. 🔥",
    "💡 On the bright side: at least your code compiles. The bar is on the floor, but you cleared it.",
    "💡 Remember: we roast the code, not the coder. You've got this. Now go fix it. 💪🔥",
    "💡 Pro tip: pretend a hacker is reading every line of your code. Because they are. 🔥",
]


def _is_roast_mode() -> bool:
    return os.environ.get("ROAST_MODE", "false").lower() == "true"


def main():
    parser = argparse.ArgumentParser(
        description="Simulate a PR security review locally (no GitHub needed)."
    )
    parser.add_argument(
        "--patch",
        type=str,
        help="Path to a unified-diff patch file to analyze.",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Path to a single source code file to scan directly.",
    )
    parser.add_argument(
        "--roast",
        action="store_true",
        help="Enable roast mode for sarcastic commentary. 🔥",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as raw JSON.",
    )

    args = parser.parse_args()

    if not args.patch and not args.file:
        parser.error("Provide either --patch or --file")

    if args.roast:
        os.environ["ROAST_MODE"] = "true"
        print("🔥 ROAST MODE ACTIVATED 🔥")
        print("   Prepare to have your feelings hurt.\n")

    if args.patch:
        _analyze_patch(args.patch, args.json_output)
    elif args.file:
        _analyze_file(args.file, args.json_output)


def _analyze_patch(patch_path: str, json_output: bool):
    """Analyze a unified diff patch file."""
    if not os.path.exists(patch_path):
        print(f"❌ Patch file not found: {patch_path}")
        sys.exit(1)

    with open(patch_path, "r") as f:
        diff = f.read()

    print(f"📄 Analyzing patch: {patch_path}")
    print(f"   Diff size: {len(diff)} characters\n")

    # Step 1: Parse diff
    analysis = analyze_code_diff(diff)
    files = analysis.get("files", [])
    print(f"📁 Found {len(files)} file(s) with changes\n")

    if not files:
        print("✅ No code changes detected.")
        return

    # Step 2: Scan each file
    all_results = []
    total_vulns = 0
    roast_index = 0  # Track which roast to pick for variety

    for file_info in files:
        filename = file_info["filename"]
        language = file_info["language"]
        code = file_info["added_code"]

        print(f"🔍 Scanning: {filename} ({language})")

        result = detect_vulnerabilities(code=code, filename=filename)
        vulns = result.get("vulnerabilities", [])
        total_vulns += len(vulns)

        file_result = {
            "filename": filename,
            "language": language,
            "vulnerabilities": vulns,
        }
        all_results.append(file_result)

        if vulns:
            print(f"   ⚠️  {len(vulns)} vulnerability(ies) found\n")
            for v in vulns:
                _print_vulnerability(v, roast_index)
                roast_index += 1
        else:
            if _is_roast_mode():
                print(f"   ✅ Clean — shocking! Someone actually knows what they're doing. 😮\n")
            else:
                print(f"   ✅ Clean\n")

    # Step 3: Validate sample code (just Python for now)
    for file_info in files:
        if file_info["language"] == "python":
            print(f"🧪 Validating syntax: {file_info['filename']}")
            val_result = validate_code(file_info["added_code"], "python")
            if val_result.get("valid"):
                print(f"   ✅ {val_result['message']}\n")
            else:
                print(f"   ❌ {val_result.get('message', val_result.get('error_message'))}\n")

    # Summary
    print("=" * 60)
    if _is_roast_mode():
        intro = random.choice(ROAST_SUMMARY_INTROS).format(n=total_vulns)
        print(f"🔥 ROAST SUMMARY: {intro}")
    else:
        print(f"📊 SUMMARY: {total_vulns} vulnerability(ies) across {len(files)} file(s)")
    print("=" * 60)

    if _is_roast_mode():
        print(f"\n{random.choice(ROAST_CLOSERS)}")

    if json_output:
        print("\n📋 JSON Output:")
        print(json.dumps(all_results, indent=2))


def _analyze_file(file_path: str, json_output: bool):
    """Analyze a single source code file directly."""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)

    with open(file_path, "r") as f:
        code = f.read()

    filename = os.path.basename(file_path)
    print(f"🔍 Scanning: {filename}")
    print(f"   Size: {len(code)} characters\n")

    result = detect_vulnerabilities(code=code, filename=filename)
    vulns = result.get("vulnerabilities", [])

    if vulns:
        if _is_roast_mode():
            intro = random.choice(ROAST_SUMMARY_INTROS).format(n=len(vulns))
            print(f"🔥 {intro}\n")
        else:
            print(f"⚠️  {len(vulns)} vulnerability(ies) found\n")

        for i, v in enumerate(vulns):
            _print_vulnerability(v, i)
    else:
        if _is_roast_mode():
            print("✅ No vulnerabilities detected. I'm genuinely impressed. Don't let it go to your head. 🔥\n")
        else:
            print("✅ No vulnerabilities detected.\n")

    if _is_roast_mode():
        print(f"\n{random.choice(ROAST_CLOSERS)}")

    if json_output:
        print("\n📋 JSON Output:")
        print(json.dumps(vulns, indent=2))


def _print_vulnerability(v: dict, index: int = 0):
    """Pretty-print a single vulnerability finding, with optional roast."""
    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }
    emoji = severity_emoji.get(v["severity"], "⚪")

    print(f"   {emoji} [{v['severity']}] {v['type']} ({v['cwe']})")
    print(f"      Line {v['line']}: {v['description']}")
    if v.get("code_snippet"):
        print(f"      Code: {v['code_snippet'][:80]}...")

    # 🔥 Add roast commentary
    if _is_roast_mode():
        roasts = ROAST_MAP.get(v["type"], [])
        if roasts:
            roast = roasts[index % len(roasts)]
            print(f"      🔥 {roast}")

    print()


if __name__ == "__main__":
    main()
