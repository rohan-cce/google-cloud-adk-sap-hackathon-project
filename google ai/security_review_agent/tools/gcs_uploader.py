# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Tool to upload artifacts to Google Cloud Storage."""

import traceback

from ..shared_libraries import constants


def upload_to_gcs(content: str, blob_name: str) -> dict:
    """Upload content to a Google Cloud Storage bucket.

    Args:
        content: The text content to upload.
        blob_name: The name/path for the blob in the bucket
                   (e.g., "scans/owner-repo/pr-42/diff.patch").

    Returns:
        dict: Status of the upload with the GCS URI.
    """
    try:
        from google.cloud import storage

        client = storage.Client(project=constants.GOOGLE_CLOUD_PROJECT)
        bucket = client.bucket(constants.GCS_BUCKET_NAME)
        blob = bucket.blob(blob_name)

        blob.upload_from_string(content, content_type="text/plain")

        gcs_uri = f"gs://{constants.GCS_BUCKET_NAME}/{blob_name}"

        return {
            "status": "success",
            "message": f"Uploaded to {gcs_uri}",
            "gcs_uri": gcs_uri,
        }

    except ImportError:
        return {
            "status": "error",
            "error_message": "google-cloud-storage not installed. Run: pip install google-cloud-storage",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Failed to upload to GCS: {str(e)}\n{traceback.format_exc()}",
        }
