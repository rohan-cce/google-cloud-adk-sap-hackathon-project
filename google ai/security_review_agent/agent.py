# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Defines the Security Review Agent — root agent definition."""

from google.adk.agents.llm_agent import Agent

from . import prompt
from .shared_libraries import constants
from .tools.code_analyzer import analyze_code_diff
from .tools.vulnerability_detector import detect_vulnerabilities
from .tools.code_rewriter import rewrite_secure_code
from .tools.code_validator import validate_code
from .tools.bigquery_logger import log_to_bigquery
from .tools.gcs_uploader import upload_to_gcs
from .tools.security_time_machine import query_security_history
from .tools.vulnerability_analytics import get_top_vulnerabilities

# Pick instruction based on roast mode
instruction = (
    prompt.ROAST_INSTRUCTION if constants.ROAST_MODE else prompt.SYSTEM_INSTRUCTION
)

root_agent = Agent(
    model=constants.MODEL,
    name=constants.AGENT_NAME,
    description=constants.DESCRIPTION,
    instruction=instruction,
    tools=[
        analyze_code_diff,
        detect_vulnerabilities,
        rewrite_secure_code,
        validate_code,
        log_to_bigquery,
        upload_to_gcs,
        query_security_history,
        get_top_vulnerabilities,
    ],
)
