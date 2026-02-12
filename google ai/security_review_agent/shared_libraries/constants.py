# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Shared constants for the Security Review Agent."""

import os

# Model
MODEL = os.getenv("MODEL", "gemini-2.0-flash")

# Agent
AGENT_NAME = "security_review_agent"
DESCRIPTION = "AI agent that scans PR diffs for security vulnerabilities and produces secure, compilable code rewrites."

# Feature flags
ROAST_MODE = os.getenv("ROAST_MODE", "false").lower() == "true"

# GCP
GOOGLE_CLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "")
GOOGLE_CLOUD_LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME", "")
BQ_DATASET = os.getenv("BQ_DATASET", "security_scans")
BQ_TABLE = os.getenv("BQ_TABLE", "scan_results")

# GitHub
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

# Server
PORT = int(os.getenv("PORT", "8080"))
