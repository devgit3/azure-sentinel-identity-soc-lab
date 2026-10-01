from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from azure.core.exceptions import HttpResponseError
from azure.identity import AzureCliCredential
from azure.monitor.ingestion import LogsIngestionClient, LogsUploadError


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_ROOT / "data" / "all_identity_events.json"


def get_required_setting(name: str) -> str:
    """Read a required setting from the terminal environment."""
    value = os.environ.get(name, "").strip()

    if not value:
        print(f"Missing setting: {name}")
        print("Add the required Azure value in the terminal and try again.")
        sys.exit(1)

    return value


def read_log_records(file_path: Path) -> list[dict[str, Any]]:
    """Read and validate the synthetic identity events."""

    if not file_path.exists():
        raise FileNotFoundError(f"Log file was not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as input_file:
        records = json.load(input_file)

    if not isinstance(records, list):
        raise ValueError("The JSON file must contain a list of records.")

    if not records:
        raise ValueError("The JSON file contains no records.")

    return records


def handle_upload_error(error: LogsUploadError) -> None:
    """Display useful information if part of the upload fails."""
    print("\nAzure rejected part of the upload.")
    print(f"Error: {error.error}")

    if error.failed_logs:
        print(f"Rejected records: {len(error.failed_logs)}")


def main() -> None:
    endpoint = get_required_setting("AZURE_LOGS_ENDPOINT")
    dcr_immutable_id = get_required_setting("AZURE_DCR_IMMUTABLE_ID")
    stream_name = get_required_setting("AZURE_STREAM_NAME")

    records = read_log_records(LOG_FILE)

    print(f"Loaded {len(records)} synthetic identity events.")
    print("Authenticating with the Azure CLI account...")

    credential = AzureCliCredential()

    client = LogsIngestionClient(
        endpoint=endpoint,
        credential=credential,
    )

    print("Sending records to Azure Monitor...")

    client.upload(
        rule_id=dcr_immutable_id,
        stream_name=stream_name,
        logs=records,
        on_error=handle_upload_error,
    )

    client.close()

    print("\nUpload request completed successfully.")
    print(f"Records submitted: {len(records)}")
    print("Destination table: IdentityLab_CL")
    print("Allow several minutes before checking Log Analytics.")


if __name__ == "__main__":
    try:
        main()

    except FileNotFoundError as error:
        print(f"\nFile error: {error}")
        sys.exit(1)

    except json.JSONDecodeError as error:
        print(f"\nJSON error: {error}")
        sys.exit(1)

    except HttpResponseError as error:
        print("\nAzure upload failed.")
        print(f"Status code: {error.status_code}")
        print(f"Reason: {error.message}")
        sys.exit(1)

    except Exception as error:
        print("\nUnexpected error.")
        print(f"{type(error).__name__}: {error}")
        sys.exit(1)