# Ingestion Guide

ForensicBuddy follows a two-layer model:

1. Preserve the original artifact as evidence and calculate SHA-256.
2. Normalize safe, structured output into timeline records when a parser is available.

The application does **not** execute evidence.

## Directly normalized formats

| Tool / source | Recommended input | ForensicBuddy behavior |
|---|---|---|
| Zeek | JSON/JSONL logs or native TSV logs | Parses records, normalizes timestamps, retains raw record JSON |
| tshark | CSV, TSV, JSON, JSONL exports | Generic structured parser; useful fields become timeline summaries |
| Wireshark | Export packet dissections to CSV/JSON | Parsed as structured output |
| Squid | access.log | Parses standard common fields including timestamp, client, result, method and URL |
| Nmap | XML output (`-oX`) | Parses host, state, protocol, port and service metadata |
| KAPE | CSV/TSV/JSON module output | Generic structured parser |
| Eric Zimmerman tools | CSV/TSV exports | Generic structured parser |
| PowerShell / Windows collection scripts | CSV/JSON/text | Generic structured/text parser |
| Cortex XSIAM / XDR | CSV/JSON exports | Generic structured parser |
| Microsoft Defender XDR | CSV/JSON exports | Generic structured parser |
| SOF-ELK / Elasticsearch-derived exports | JSON/JSONL/CSV | Generic structured parser |
| Security Onion / Malcolm | JSON/JSONL/CSV exports | Generic structured parser |
| GRASSMARLIN | Exported structured/text results | Generic structured/text parser |
| Arkime | Exported JSON/CSV session data | Generic structured parser |

## Preserved without deep parsing

These should generally be analyzed in the specialist tool that understands the format, with derived CSV/JSON/text ingested alongside the original:

- PCAP / PCAPNG
- EVTX
- Windows Registry hives
- Memory images
- Disk images
- E01/AFF forensic images
- PST/OST
- SQLite databases when direct parsing is not appropriate
- Browser databases
- Executables, DLLs and scripts collected as evidence
- Archives
- Proprietary tool databases

Example workflow:

```text
evidence.pcap
  -> preserve original in ForensicBuddy as E-0001
  -> analyze with tshark / Zeek / Wireshark
  -> export zeek conn.log + dns.log or tshark CSV/JSON
  -> ingest derived files as E-0002 / E-0003
  -> link findings to E-0001, E-0002, E-0003
```

## FOR572-oriented examples

### Zeek JSON

```bash
zeek -r evidence.pcap LogAscii::use_json=T
```

Upload the resulting `.log`/JSON output. If using native Zeek TSV, ForensicBuddy reads the `#fields` header.

### tshark CSV

```bash
tshark -r evidence.pcap -T fields -E header=y -E separator=, -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e dns.qry.name > tshark.csv
```

### Nmap XML

```bash
nmap -sV -oX scan.xml 10.0.0.0/24
```

### Squid

Upload a standard `access.log` directly. Custom `logformat` layouts may be preserved as text or exported to CSV/JSON for deterministic field mapping.

## Parser extension pattern

Add a parser in `app.py` that:

1. Treats input only as data.
2. Places bounds on record count and decompression.
3. Returns a parser name and list of dictionaries.
4. Does not modify the original evidence object.
5. Does not invoke shell commands against uploaded evidence.
6. Stores enough source context to reconstruct how a normalized event maps back to the evidence.

ForensicBuddy currently caps imported records from one evidence item at 100,000 to prevent accidental browser/database overload in the MVP.
