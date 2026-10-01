# Project notes

## Detection logic

### Password spraying
Groups failed sign-ins by source IP and a fixed 15-minute bin. A result is returned when both the failed-attempt count and the number of distinct targeted users meet the laboratory thresholds.

### Rapid location change
Orders successful sign-ins by user and timestamp, then compares each event with the previous sign-in for the same account. A detection is returned when the country changes within 60 minutes.

### Privilege escalation
Filters successful audit-style role assignments for high-impact administrator roles where the controlled approval flag is false.

## Investigation workflow

```text
evidence -> ingestion -> KQL -> Sentinel alert -> incident -> entities -> analyst review -> classification -> forensic timeline
```

## Evaluation interpretation

The controlled evaluation is intended to demonstrate workflow correctness and technical feasibility. It does not establish production detection accuracy, enterprise false-positive rates or operational alert latency.
