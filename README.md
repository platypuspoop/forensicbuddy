# ForensicBuddy

ForensicBuddy is a self-hosted DFIR case and evidence management application for cybersecurity teams. It catalogs investigation evidence, normalizes common forensic/log outputs, records chain-of-custody activity, manages findings and timelines, and builds investigation reports.

## Core capabilities

- Case management with classification and status
- Evidence catalog with SHA-256 integrity hashes
- Optional AES-compatible Fernet encryption for evidence at rest
- Chain-of-custody events and hash-chained application audit records
- Role-based access: admin, investigator, reviewer
- Findings with severity, confidence, impact, recommendation, and evidence references
- Timeline/event ingestion from common DFIR outputs
- HTML report preview and Markdown report export
- Parsers/detection for:
  - Zeek JSON / JSONL and Zeek TSV
  - Squid access.log
  - CSV outputs from KAPE, Zimmerman tools, Defender/XDR, XSIAM and other tools
  - JSON/NDJSON logs
  - Nmap XML
  - Generic text logs
- Raw evidence preservation for PCAPs, EVTX, registry hives, disk/memory images, archives, and other binary artifacts

The parser list is intentionally extensible. Unsupported files are still preserved as evidence and can be documented in the case.

## Important compliance note

ForensicBuddy is designed to **support** HIPAA Security Rule safeguards and NIST SP 800-53 Rev. 5 controls. Installing this application does not, by itself, make a system or organization compliant. Production deployment requires organization-specific risk analysis, policies, access authorization, infrastructure hardening, TLS, backup/retention controls, vulnerability management, logging/monitoring, incident response, workforce controls, and appropriate administrative/physical safeguards.

Do not place real ePHI in a public Git repository. Evidence is stored outside the repository at runtime.

## Quick start

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/platypuspoop/forensicbuddy.git
cd forensicbuddy
python -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set required secrets

Generate an evidence encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set environment variables:

```bash
export SECRET_KEY='replace-with-a-long-random-secret'
export EVIDENCE_FERNET_KEY='paste-generated-key'
export BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-strong-temporary-password'
```

PowerShell:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
$env:EVIDENCE_FERNET_KEY = "paste-generated-key"
$env:BOOTSTRAP_ADMIN_PASSWORD = "replace-with-a-strong-temporary-password"
```

### 4. Run

```bash
python app.py
```

Open `http://127.0.0.1:5000` and sign in as `admin` with the bootstrap password.

The bootstrap account is created only when no users exist. Change the password immediately after first login or replace local authentication with your enterprise identity provider before production use.

## Docker

```bash
docker compose up --build
```

Create a `.env` file first using `.env.example`. Use a reverse proxy or ingress with TLS for production. Never expose the development server directly to the Internet.

## Evidence handling model

When a file is uploaded:

1. The application reads the original bytes.
2. A SHA-256 hash is calculated over the original evidence.
3. Metadata and collection context are recorded.
4. The file is encrypted with Fernet when `EVIDENCE_FERNET_KEY` is configured.
5. The encrypted blob is written under a random UUID-based filename.
6. A chain-of-custody record and application audit event are created.
7. If the format is recognized, normalized events are extracted for investigation/search. The original file remains the authoritative evidence.

For production, place `INSTANCE_PATH` and `EVIDENCE_PATH` on encrypted, access-controlled storage with backups and retention appropriate to your policy.

## Supported input examples

The application is designed to accept exports/results from tools including Wireshark/tshark, Zeek, tcpdump/dumpcap, Arkime, Malcolm, Security Onion, GRASSMARLIN, Nmap, Squid, KAPE, Eric Zimmerman utilities, PowerShell, Microsoft Defender XDR, Cortex XSIAM/XDR, SOF-ELK, and similar tools. Binary formats that are not parsed remain cataloged evidence.

Do not execute uploaded evidence inside the web application. ForensicBuddy parses text/structured formats only and treats binaries as opaque evidence.

## Production hardening

At minimum:

- TLS 1.2+ at a trusted reverse proxy/load balancer
- Enterprise SSO/MFA in front of or integrated with the application
- Least-privilege application/service accounts
- Encrypted database and evidence volumes
- Secrets in a managed secret store, not environment files committed to source
- Centralized audit-log forwarding with retention and alerting
- Regular backup/restore testing
- Dependency and container scanning
- OS/container hardening
- EDR/monitoring on the host
- Network segmentation and restricted administrative access
- Formal retention/disposal procedures
- Independent control assessment

See [docs/CONTROL-MAPPING.md](docs/CONTROL-MAPPING.md) and [SECURITY.md](SECURITY.md).

## Development

```bash
pytest -q
```

The local SQLite database and evidence directory are created under `instance/` by default and are excluded from Git.

## License

No license has been selected yet. Add an approved license before redistribution.
