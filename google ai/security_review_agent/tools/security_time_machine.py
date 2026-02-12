# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Security Time Machine — query BigQuery for historical security scan trends."""

import json
import traceback

from ..shared_libraries import constants


def query_security_history(repo: str, num_prs: int = 10) -> dict:
    """Query the last N PR security scans for a repo and summarize trends.

    This tool queries BigQuery to retrieve historical scan data, aggregates
    vulnerability counts over time, and returns structured trend information
    that the agent can use to generate a natural language summary.

    Args:
        repo: The repository full name (e.g., "owner/repo").
        num_prs: Number of recent PR scans to analyze (default: 10).

    Returns:
        dict: Historical scan data with trend analysis including:
              - scans: List of recent scan records
              - trends: Aggregated vulnerability trends over time
              - oldest/newest scan comparison
    """
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=constants.GOOGLE_CLOUD_PROJECT)
        table_id = f"{constants.GOOGLE_CLOUD_PROJECT}.{constants.BQ_DATASET}.{constants.BQ_TABLE}"

        query = f"""
        SELECT
            repo,
            pr_number,
            pr_author,
            vulnerabilities_found,
            vulnerability_types,
            severity_summary,
            scan_timestamp,
            status
        FROM `{table_id}`
        WHERE repo = @repo
        ORDER BY scan_timestamp DESC
        LIMIT @num_prs
        """

        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("repo", "STRING", repo),
                bigquery.ScalarQueryParameter("num_prs", "INT64", num_prs),
            ]
        )

        results = client.query(query, job_config=job_config)
        rows = [dict(row) for row in results]

        if not rows:
            return {
                "status": "success",
                "message": f"No scan history found for '{repo}'.",
                "scans": [],
                "trends": {},
            }

        # Compute trends
        total_vulns_over_time = []
        all_vuln_types = {}

        for row in rows:
            total_vulns_over_time.append({
                "pr_number": row["pr_number"],
                "vulnerabilities_found": row["vulnerabilities_found"],
                "timestamp": str(row["scan_timestamp"]),
            })

            # Count vulnerability types
            if row.get("vulnerability_types"):
                for vtype in row["vulnerability_types"].split(","):
                    vtype = vtype.strip()
                    if vtype:
                        all_vuln_types[vtype] = all_vuln_types.get(vtype, 0) + 1

        # Compare oldest vs newest
        newest = rows[0]
        oldest = rows[-1]

        oldest_vulns = oldest.get("vulnerabilities_found", 0)
        newest_vulns = newest.get("vulnerabilities_found", 0)

        if oldest_vulns > 0:
            improvement_pct = round(
                ((oldest_vulns - newest_vulns) / oldest_vulns) * 100, 1
            )
        else:
            improvement_pct = 0.0

        trends = {
            "total_scans": len(rows),
            "oldest_pr": {
                "pr_number": oldest.get("pr_number"),
                "vulnerabilities": oldest_vulns,
                "timestamp": str(oldest.get("scan_timestamp")),
            },
            "newest_pr": {
                "pr_number": newest.get("pr_number"),
                "vulnerabilities": newest_vulns,
                "timestamp": str(newest.get("scan_timestamp")),
            },
            "improvement_percentage": improvement_pct,
            "vulnerability_type_counts": all_vuln_types,
            "vulns_over_time": total_vulns_over_time,
        }

        return {
            "status": "success",
            "message": (
                f"Retrieved {len(rows)} scan(s) for '{repo}'. "
                f"Vulnerability count changed from {oldest_vulns} → {newest_vulns} "
                f"({improvement_pct}% improvement)."
            ),
            "scans": rows,
            "trends": trends,
        }

    except ImportError:
        return {
            "status": "error",
            "error_message": "google-cloud-bigquery not installed.",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Failed to query security history: {str(e)}\n{traceback.format_exc()}",
        }
