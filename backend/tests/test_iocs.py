"""IOC extraction covers the indicator types the ingest path must recognize."""

from false_alarm.ingest.iocs import extract_iocs, extract_iocs_from_text


def test_extracts_each_indicator_type():
    text = (
        "Phish https://evil.example/drop from 203.0.113.50 "
        "mail analyst@corp.example hash 0123456789abcdef0123456789abcdef "
        "sha1 0123456789abcdef0123456789abcdef01234567 "
        "sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
        "host srv-01"
    )
    found = {(item.type, item.value) for item in extract_iocs_from_text(text)}
    assert ("ipv4", "203.0.113.50") in found
    assert ("url", "https://evil.example/drop") in found
    assert ("domain", "evil.example") in found
    assert ("email", "analyst@corp.example") in found
    assert ("domain", "corp.example") in found
    assert ("md5", "0123456789abcdef0123456789abcdef") in found
    assert ("sha1", "0123456789abcdef0123456789abcdef01234567") in found
    assert ("sha256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") in found
    assert ("hostname", "srv-01") in found
    assert sum(1 for item in found if item[0] == "md5") == 1
    assert sum(1 for item in found if item[0] == "sha1") == 1
    assert ("ipv4", "999.1.1.1") not in {
        (item.type, item.value) for item in extract_iocs_from_text("bad 999.1.1.1 address")
    }


def test_structured_hostname_and_hash_fields():
    iocs = extract_iocs(
        {
            "hostname": "WS-JSMITH",
            "src_ip": "10.0.5.10",
            "file_hashes": ["0123456789ABCDEF0123456789ABCDEF"],
            "domains": ["files.example"],
            "urls": ["https://files.example/a"],
            "description": "see srv-01",
        }
    )
    found = {(item.type, item.value) for item in iocs}
    assert ("hostname", "WS-JSMITH") in found
    assert ("ipv4", "10.0.5.10") in found
    assert ("md5", "0123456789abcdef0123456789abcdef") in found
    assert ("domain", "files.example") in found
    assert ("url", "https://files.example/a") in found
    assert ("hostname", "srv-01") in found
