"""Indicators are real indicators: no file names or account names, IPv6 included, and all of them looked up."""

import pytest
from factories import ATTACKER, alert_payload, flow, intel, investigate, login, use_logs

from false_alarm.ingest import ingest_alert
from false_alarm.ingest.iocs import extract_iocs, extract_iocs_from_text
from false_alarm.service import load_scenario, run_investigation
from false_alarm.util import is_external_ip


def _found(iocs) -> set[tuple[str, str]]:
    return {(item.type, item.value) for item in iocs}


def test_dotted_usernames_are_not_domains():
    found = _found(extract_iocs({"username": "jane.doe", "description": "jane.doe failed to sign in"}))
    assert ("domain", "jane.doe") not in found


@pytest.mark.parametrize("name", ["powershell.exe", "invoice.pdf", "payload.dll", "report.docx", "run.ps1", "a.json"])
def test_file_names_are_not_domains(name):
    assert [item for item in extract_iocs_from_text(f"ran {name} today") if item.type == "domain"] == []


def test_a_url_contributes_only_its_host_as_a_domain():
    found = _found(extract_iocs_from_text("fetched https://evil.example/drop/stage2.example?next=cdn.example"))
    assert ("url", "https://evil.example/drop/stage2.example?next=cdn.example") in found
    assert {value for kind, value in found if kind == "domain"} == {"evil.example"}


def test_real_domains_and_email_domains_are_kept():
    found = _found(extract_iocs_from_text("beacon to c2.evil.example, mail from x@corp.example"))
    assert {("domain", "c2.evil.example"), ("domain", "corp.example"), ("email", "x@corp.example")} <= found


def test_ipv6_is_extracted_from_text_and_fields():
    found = _found(extract_iocs({"src_ip": "2001:DB8:0::1", "description": "then 2001:db8::bad at 14:26:00 via 00:1a:2b:3c:4d:5e"}))
    assert ("ipv6", "2001:db8::1") in found
    assert ("ipv6", "2001:db8::bad") in found
    assert {value for kind, value in found if kind == "ipv6"} == {"2001:db8::1", "2001:db8::bad"}


def test_an_invalid_ip_field_is_dropped_with_a_warning():
    result = ingest_alert(alert_payload(src_ip="999.1.1.1", dst_ip="not-an-ip"))
    assert result.errors == []
    assert result.alert["src_ip"] is None and result.alert["dst_ip"] is None
    assert {item["field"] for item in result.warnings} >= {"src_ip", "dst_ip"}


def test_ip_fields_are_stored_in_canonical_form():
    assert ingest_alert(alert_payload(src_ip="2001:DB8:0:0::1")).alert["src_ip"] == "2001:db8::1"


@pytest.mark.parametrize(
    "address,external",
    [
        ("203.0.113.50", True),
        ("198.51.100.77", True),
        ("192.0.2.1", True),
        ("2001:db8::1", True),
        ("8.8.8.8", True),
        ("10.0.0.1", False),
        ("172.16.4.4", False),
        ("192.168.1.1", False),
        ("100.64.0.1", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("fd00::1", False),
        ("fe80::1", False),
        ("::1", False),
        ("not-an-ip", False),
    ],
)
def test_documentation_ranges_are_external_and_private_ranges_are_not(address, external):
    assert is_external_ip(address) is external


def test_the_demo_exfiltration_address_is_looked_up():
    result = run_investigation(load_scenario("account_compromise").alert["id"])
    rated = {item["raw"]["indicator"]: item["raw"]["reputation"] for item in result["evidence"] if item["source_type"] == "threat_intel"}
    assert rated.get("198.51.100.77") == "malicious"
    assert result["assessment"]["verdict"] == "confirmed_threat"


def test_indicators_found_after_the_first_lookup_are_looked_up(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("13:50")],
        endpoint=[{"timestamp": "2026-04-12T13:52:00Z", "username": "bob", "hostname": "WS-BOB", "action": "process", "file_hash": "c" * 32}],
        firewall=[flow("13:58", dst_ip="91.2.3.4", direction="outbound", bytes=10)],
        threat_intel=[intel(ATTACKER, "clean"), intel("91.2.3.4", "malicious")],
    )
    result = investigate(name="Malware found on host", description="x", mitre_techniques=["T1204"])
    looked_up = {ioc for step in result["steps"] if step["tool"] == "lookup_threat_intel" for ioc in step["arguments"]["iocs"]}
    assert {"91.2.3.4", "c" * 32} <= looked_up
    assert len([step for step in result["steps"] if step["tool"] == "lookup_threat_intel"]) >= 2
    assert result["assessment"]["verdict"] == "confirmed_threat"
