# Security

This repository contains defensive-security lab material only.

## Do not commit

- Azure access tokens
- client secrets
- workspace shared keys
- real passwords
- private tenant information
- subscription IDs unless intentionally redacted
- live production identities
- `.env` files containing real values

The upload workflow uses `AzureCliCredential` and expects environment-specific Azure configuration to be supplied outside the source code.

If you fork or reuse the project, run it only in systems and cloud resources you are authorised to test.
