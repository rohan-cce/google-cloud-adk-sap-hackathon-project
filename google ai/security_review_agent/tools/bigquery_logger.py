# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tool to log security scan results to BigQuery."""

import datetime
import json
import traceback

from ..shared_libraries import constants


def log_to_bigquery(scan_record: dict) -> dict:
    """Insert a security scan record into BigQuery.

    Args:
        scan_record: A dictionary containing scan result data:
            - repo (str): Repository full name (e.g., "owner/repo")
            - pr_number (int): Pull request number
            - pr_author (str): PR author username
            - vulnerabilities_found (int): Total vulnerabilities detected
            - vulnerability_types (str): Comma-separated list of vuln types
            - severity_summary (str): Summary of severity counts
            - status (str): "clean" or "vulnerabilities_found"
            - diff_gcs_uri (str): GCS URI of the uploaded diff
            - remediation_gcs_uri (str): GCS URI of the remediated code

    Returns:
        dict: Status of the BigQuery insert operation.
    """
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=constants.GOOGLE_CLOUD_PROJECT)
        table_id = f"{constants.GOOGLE_CLOUD_PROJECT}.{constants.BQ_DATASET}.{constants.BQ_TABLE}"

        row = {
            "repo": scan_record.get("repo", "unknown"),
            "pr_number": scan_record.get("pr_number", 0),
            "pr_author": scan_record.get("pr_author", "unknown"),
            "vulnerabilities_found": scan_record.get("vulnerabilities_found", 0),
            "vulnerability_types": scan_record.get("vulnerability_types", ""),
            "severity_summary": scan_record.get("severity_summary", ""),
            "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": scan_record.get("status", "unknown"),
            "diff_gcs_uri": scan_record.get("diff_gcs_uri", ""),
            "remediation_gcs_uri": scan_record.get("remediation_gcs_uri", ""),
            "roast_mode": scan_record.get("roast_mode", False),
        }

        errors = client.insert_rows_json(table_id, [row])

        if errors:
            return {
                "status": "error",
                "error_message": f"BigQuery insert errors: {json.dumps(errors)}",
            }

        return {
            "status": "success",
            "message": f"Scan record logged to BigQuery table {table_id}.",
            "row": row,
        }

    except ImportError:
        return {
            "status": "error",
            "error_message": "google-cloud-bigquery not installed. Run: pip install google-cloud-bigquery",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Failed to log to BigQuery: {str(e)}\n{traceback.format_exc()}",
        }
