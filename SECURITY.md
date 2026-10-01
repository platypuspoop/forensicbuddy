# Security Policy

## Scope

ForensicBuddy is intended to store sensitive DFIR case information and may be deployed in environments that process electronic protected health information (ePHI). Treat the application, database, evidence storage, backups, keys, and exported reports as sensitive security assets.

## Production requirements

The development server is not approved for production. Production deployments should use:

- TLS 1.2 or later through an approved reverse proxy/load balancer
- Enterprise identity with MFA
- Encrypted storage and encrypted backups
- Managed secrets/keys
- Central security logging and monitoring
- Least-privilege service identities
- Network segmentation and administrative access restrictions
- EDR/host monitoring
- Patch and dependency management
- Tested backups and recovery procedures

## Evidence safety

Uploaded evidence is never intentionally executed. Structured formats are parsed as data. Binary evidence should be analyzed in isolated forensic tooling and its derived output ingested into ForensicBuddy.

The application calculates SHA-256 over the original upload before writing it to evidence storage. When encryption is configured, encrypted bytes are stored under randomized filenames; the original hash remains the integrity reference.

## Secrets

Never commit:

- SECRET_KEY
- EVIDENCE_FERNET_KEY
- passwords
- OAuth/OIDC client secrets
- database credentials
- certificates/private keys
- ePHI or case evidence

Use an approved secret manager for production.

## Reporting security issues

Do not post vulnerability details containing sensitive deployment information, evidence, credentials or ePHI to a public GitHub issue. Use the organization's approved private security reporting process.
