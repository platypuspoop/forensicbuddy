import json
import app as forensicbuddy

def test_jsonl_parser():
    data = b'{"ts": 1710000000.1, "uid": "C1", "query": "example.org"}\n{"ts": 1710000001.1, "uid": "C2", "query": "test.org"}\n'
    parser, rows = forensicbuddy.parse_evidence("dns.log.jsonl", data)
    assert parser == "Zeek JSON"
    assert len(rows) == 2
    assert rows[0]["query"] == "example.org"

def test_zeek_tsv_parser():
    text = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\n1710000000.1\tC1\t10.0.0.5\t8.8.8.8\n"
    parser, rows = forensicbuddy.parse_evidence("conn.log", text.encode())
    assert parser == "Zeek TSV"
    assert rows[0]["uid"] == "C1"

def test_squid_parser():
    line = "1710000000.100 22 10.0.0.5 TCP_MISS/200 1234 GET https://example.org/ - HIER_DIRECT/1.2.3.4 text/html\n"
    parser, rows = forensicbuddy.parse_evidence("access.log", line.encode())
    assert parser == "Squid access.log"
    assert rows[0]["method"] == "GET"
    assert rows[0]["url"] == "https://example.org/"

def test_nmap_parser():
    xml = b'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port></ports></host></nmaprun>'
    parser, rows = forensicbuddy.parse_evidence("scan.xml", xml)
    assert parser == "Nmap XML"
    assert rows[0]["port"] == "443"
    assert rows[0]["service"] == "https"

def test_summary_prefers_useful_fields():
    summary = forensicbuddy.summary_for({"query":"bad.example","uid":"C1","rcode_name":"NOERROR"})
    assert "query=bad.example" in summary
