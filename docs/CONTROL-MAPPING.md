# HIPAA and NIST SP 800-53 Control Mapping

This document describes how ForensicBuddy features can support technical and operational controls. It is not a certification or assertion that a deployment is compliant.

## HIPAA Security Rule

| HIPAA safeguard | ForensicBuddy support | Deployment responsibility |
|---|---|---|
| 45 CFR 164.312(a) Access Control | Authenticated users, roles (admin/investigator/reviewer), least-function role separation, secure session cookies | Integrate enterprise SSO/MFA, unique identities, account lifecycle, emergency access, session policy |
| 45 CFR 164.312(b) Audit Controls | Hash-chained application audit log records login, case, evidence, verification, user, and report activity | Forward logs to protected centralized logging/SIEM; define retention and review procedures |
| 45 CFR 164.312(c)(1) Integrity | SHA-256 over original evidence; on-demand verification; encrypted original evidence separated from normalized events | Protect host/storage/keys; backup integrity; formal evidence-handling SOP |
| 45 CFR 164.312(d) Person or Entity Authentication | Local password authentication for MVP | Replace/integrate with enterprise identity, MFA and approved identity proofing for production |
| 45 CFR 164.312(e) Transmission Security | Secure-cookie option and deployment guidance | TLS termination/certificates, approved cryptography, network protection are infrastructure controls |

## NIST SP 800-53 Rev. 5

The following controls are particularly relevant. Exact applicability depends on the selected baseline and organizational tailoring.

| Control | Relationship to ForensicBuddy |
|---|---|
| AC-2 Account Management | User records and roles exist in the MVP; production should integrate authoritative enterprise identity and lifecycle processes |
| AC-3 Access Enforcement | Application routes enforce authenticated role checks |
| AC-6 Least Privilege | Investigator, reviewer, and administrator permissions are separated |
| AU-2 Event Logging | Security-relevant application events are captured |
| AU-3 Content of Audit Records | Audit events include timestamp, user, action, object, detail, and integrity hash |
| AU-6 Audit Record Review, Analysis, and Reporting | Audit view is provided; production should centralize and alert through the organization's SIEM |
| AU-9 Protection of Audit Information | Audit events are hash-chained; database/storage access must also be restricted and protected |
| AU-10 Non-repudiation | Evidence hashes and custody records improve traceability; stronger signatures/PKI may be required for organization-specific non-repudiation needs |
| CM-2 Baseline Configuration | Containerization and configuration documentation provide a reproducible starting point |
| CM-6 Configuration Settings | Security-relevant settings are environment controlled; production baselines should enforce approved values |
| IA-2 Identification and Authentication | Local authentication exists for MVP; enterprise SSO/MFA is recommended for production |
| IR-4 Incident Handling | Cases, evidence, findings, and timelines support incident investigation workflows |
| IR-5 Incident Monitoring | Case/timeline structures support monitoring investigation progress; enterprise incident processes remain external |
| MP-4 Media Storage | Evidence storage is separate and can be encrypted; deployment must provide protected media/storage controls |
| MP-5 Media Transport | Chain-of-custody records support transfers; actual transport safeguards are procedural/infrastructure controls |
| RA-5 Vulnerability Monitoring and Scanning | Dependency/container scanning should be added to CI/CD and deployment operations |
| SC-8 Transmission Confidentiality and Integrity | Requires TLS/reverse proxy/network controls in production |
| SC-12 Cryptographic Key Establishment and Management | Evidence encryption uses a key supplied externally; production keys should be managed by an approved secret/key management service |
| SC-13 Cryptographic Protection | Evidence blobs can be encrypted with Fernet; volume/database/backups should also use approved encryption |
| SI-7 Software, Firmware, and Information Integrity | SHA-256 evidence verification and hash-chained application audit events support integrity validation |

## Evidence integrity model

ForensicBuddy deliberately separates:

1. **Original evidence bytes** - retained as the authoritative evidence object.
2. **Metadata** - source, collector, tool, collection time, case association and notes.
3. **Integrity value** - SHA-256 calculated before evidence storage.
4. **Normalized events** - convenience records produced from parsable text/structured outputs.
5. **Analyst findings** - conclusions linked back to evidence identifiers.
6. **Audit/custody records** - traceability of ingestion, verification, reports and user actions.

Normalized data is never a substitute for the original evidence.

## Production compliance checklist

Before handling ePHI or regulated evidence, document and approve:

- System security plan and risk analysis
- Information classification and minimum-necessary access model
- Enterprise SSO/MFA and joiner/mover/leaver processes
- TLS and certificate management
- Database, filesystem, backup and key encryption
- Centralized immutable/retained audit logging
- Backup/restore and continuity testing
- Vulnerability/patch management
- Host/container hardening
- Network segmentation
- Evidence retention and destruction
- Incident response and breach-notification workflows
- Workforce authorization/training
- Business associate agreements where required
- Periodic control assessment and evidence of effectiveness
