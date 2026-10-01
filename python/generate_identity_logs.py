from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# Find the main project folder, then create/find the data folder.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIRECTORY = PROJECT_ROOT / "data"
DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)


def utc_text(date_time: datetime) -> str:
    """Convert a datetime into the UTC format commonly used in cloud logs."""
    return date_time.isoformat().replace("+00:00", "Z")


def create_event(
    event_time: datetime,
    scenario: str,
    event_type: str,
    user: str = "",
    source_ip: str = "",
    country: str = "",
    city: str = "",
    device: str = "",
    application: str = "",
    result: str = "",
    failure_reason: str = "",
    operation_name: str = "",
    actor: str = "",
    target_user: str = "",
    role_name: str = "",
    approved_change: bool = False,
    malicious: bool = False,
    severity: str = "Informational",
    notes: str = "",
    correlation_id: str = "",
) -> dict[str, Any]:
    """Create one Entra-style identity or audit event."""

    return {
        "TimeGenerated": utc_text(event_time),
        "EventId": str(uuid.uuid4()),
        "CorrelationId": correlation_id or str(uuid.uuid4()),
        "Scenario": scenario,
        "EventType": event_type,
        "UserPrincipalName": user,
        "SourceIPAddress": source_ip,
        "Country": country,
        "City": city,
        "DeviceName": device,
        "Application": application,
        "Result": result,
        "FailureReason": failure_reason,
        "OperationName": operation_name,
        "ActorUserPrincipalName": actor,
        "TargetUserPrincipalName": target_user,
        "RoleName": role_name,
        "IsApprovedChange": approved_change,
        "IsMalicious": malicious,
        "Severity": severity,
        "Notes": notes,
    }


# Start the simulated story one hour before the current time.
now = datetime.now(timezone.utc).replace(microsecond=0)
start_time = now - timedelta(hours=1)

normal_correlation = str(uuid.uuid4())
spray_correlation = str(uuid.uuid4())
travel_correlation = str(uuid.uuid4())
privilege_correlation = str(uuid.uuid4())


# -------------------------------------------------------------------
# DATASET 1: NORMAL ACTIVITY
# Ordinary sign-ins that should not create serious security alerts.
# -------------------------------------------------------------------

normal_activity = [
    create_event(
        start_time + timedelta(minutes=2),
        scenario="Normal Activity",
        event_type="SignIn",
        user="devika.user1@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.10",
        country="United Kingdom",
        city="London",
        device="LAB-LAPTOP-01",
        application="Microsoft Azure Portal",
        result="Success",
        malicious=False,
        notes="Normal successful login from the expected location.",
        correlation_id=normal_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=5),
        scenario="Normal Activity",
        event_type="SignIn",
        user="devika.user2@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.11",
        country="United Kingdom",
        city="London",
        device="LAB-LAPTOP-02",
        application="Microsoft 365",
        result="Success",
        malicious=False,
        notes="Normal successful login.",
        correlation_id=normal_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=8),
        scenario="Normal Activity",
        event_type="SignIn",
        user="devika.user3@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.12",
        country="United Kingdom",
        city="London",
        device="LAB-LAPTOP-03",
        application="Microsoft Teams",
        result="Failure",
        failure_reason="Incorrect password",
        malicious=False,
        notes="One ordinary password mistake.",
        correlation_id=normal_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=9),
        scenario="Normal Activity",
        event_type="SignIn",
        user="devika.user3@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.12",
        country="United Kingdom",
        city="London",
        device="LAB-LAPTOP-03",
        application="Microsoft Teams",
        result="Success",
        malicious=False,
        notes="The genuine user corrected the password.",
        correlation_id=normal_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=12),
        scenario="Normal Activity",
        event_type="SignIn",
        user="soc.analyst@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.20",
        country="United Kingdom",
        city="London",
        device="SOC-WORKSTATION-01",
        application="Microsoft Sentinel",
        result="Success",
        malicious=False,
        notes="Normal SOC analyst login.",
        correlation_id=normal_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=15),
        scenario="Normal Activity",
        event_type="Audit",
        operation_name="Update user profile",
        actor="soc.admin@devikasoclab.onmicrosoft.com",
        target_user="devika.user1@devikasoclab.onmicrosoft.com",
        result="Success",
        approved_change=True,
        malicious=False,
        notes="Approved administrative profile update.",
        correlation_id=normal_correlation,
    ),
]


# -------------------------------------------------------------------
# DATASET 2: PASSWORD SPRAYING
# One source IP tries a password against several different accounts.
# -------------------------------------------------------------------

password_spray_users = [
    "devika.user1@devikasoclab.onmicrosoft.com",
    "devika.user2@devikasoclab.onmicrosoft.com",
    "devika.user3@devikasoclab.onmicrosoft.com",
    "finance.user@devikasoclab.onmicrosoft.com",
    "hr.user@devikasoclab.onmicrosoft.com",
    "support.user@devikasoclab.onmicrosoft.com",
    "soc.admin@devikasoclab.onmicrosoft.com",
]

password_spray = []

for minute_number, user_name in enumerate(password_spray_users, start=20):
    password_spray.append(
        create_event(
            start_time + timedelta(minutes=minute_number),
            scenario="Password Spraying",
            event_type="SignIn",
            user=user_name,
            source_ip="203.0.113.50",
            country="Unknown",
            city="Unknown",
            device="Unknown Device",
            application="Microsoft 365",
            result="Failure",
            failure_reason="Invalid username or password",
            malicious=True,
            severity="Medium",
            notes="Repeated failed login from the same source IP.",
            correlation_id=spray_correlation,
        )
    )

password_spray.append(
    create_event(
        start_time + timedelta(minutes=28),
        scenario="Password Spraying",
        event_type="SignIn",
        user="support.user@devikasoclab.onmicrosoft.com",
        source_ip="203.0.113.50",
        country="Unknown",
        city="Unknown",
        device="Unknown Device",
        application="Microsoft 365",
        result="Success",
        malicious=True,
        severity="High",
        notes="Successful login after repeated password-spraying attempts.",
        correlation_id=spray_correlation,
    )
)


# -------------------------------------------------------------------
# DATASET 3: SUSPICIOUS SIGN-IN / IMPOSSIBLE TRAVEL
# The same account appears in London and Singapore five minutes apart.
# -------------------------------------------------------------------

suspicious_signin = [
    create_event(
        start_time + timedelta(minutes=35),
        scenario="Suspicious Sign-In",
        event_type="SignIn",
        user="devika.user2@devikasoclab.onmicrosoft.com",
        source_ip="192.0.2.11",
        country="United Kingdom",
        city="London",
        device="LAB-LAPTOP-02",
        application="Microsoft Azure Portal",
        result="Success",
        malicious=False,
        notes="Expected successful login from London.",
        correlation_id=travel_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=40),
        scenario="Suspicious Sign-In",
        event_type="SignIn",
        user="devika.user2@devikasoclab.onmicrosoft.com",
        source_ip="198.51.100.88",
        country="Singapore",
        city="Singapore",
        device="UNRECOGNISED-DEVICE",
        application="Microsoft Azure Portal",
        result="Success",
        malicious=True,
        severity="High",
        notes="The same account appeared in Singapore five minutes after London.",
        correlation_id=travel_correlation,
    ),
]


# -------------------------------------------------------------------
# DATASET 4: PRIVILEGE ESCALATION
# A normal account is unexpectedly given a powerful administrator role.
# -------------------------------------------------------------------

privilege_escalation = [
    create_event(
        start_time + timedelta(minutes=45),
        scenario="Privilege Escalation",
        event_type="SignIn",
        user="compromised.admin@devikasoclab.onmicrosoft.com",
        source_ip="198.51.100.120",
        country="Unknown",
        city="Unknown",
        device="UNRECOGNISED-DEVICE",
        application="Microsoft Entra Admin Centre",
        result="Success",
        malicious=True,
        severity="High",
        notes="Suspicious account signed in before performing an admin action.",
        correlation_id=privilege_correlation,
    ),
    create_event(
        start_time + timedelta(minutes=48),
        scenario="Privilege Escalation",
        event_type="Audit",
        operation_name="Add member to role",
        actor="compromised.admin@devikasoclab.onmicrosoft.com",
        target_user="devika.user3@devikasoclab.onmicrosoft.com",
        role_name="Global Administrator",
        result="Success",
        approved_change=False,
        malicious=True,
        severity="High",
        notes="Unapproved assignment of a highly privileged administrator role.",
        correlation_id=privilege_correlation,
    ),
]


datasets = {
    "normal_activity.json": normal_activity,
    "password_spray.json": password_spray,
    "suspicious_signin.json": suspicious_signin,
    "privilege_escalation.json": privilege_escalation,
}

all_identity_events = []

for file_name, events in datasets.items():
    output_path = DATA_DIRECTORY / file_name

    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(events, output_file, indent=2, ensure_ascii=False)

    all_identity_events.extend(events)
    print(f"Created {file_name}: {len(events)} events")


# Sort the combined file into time order.
all_identity_events.sort(key=lambda event: event["TimeGenerated"])

combined_path = DATA_DIRECTORY / "all_identity_events.json"

with combined_path.open("w", encoding="utf-8") as output_file:
    json.dump(all_identity_events, output_file, indent=2, ensure_ascii=False)

print(f"Created all_identity_events.json: {len(all_identity_events)} events")
print(f"Files saved inside: {DATA_DIRECTORY}")
print("Synthetic identity-log generation completed successfully.")