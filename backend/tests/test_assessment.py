"""Verdict rules, exercised through whole investigations."""

import pytest
from factories import ATTACKER, VPN, failures, finance_access, flow, intel, investigate, login, use_logs

CLEAN = [intel(ATTACKER, "clean"), intel(VPN, "clean")]
BRUTE_FORCE = [*failures(25), login("13:56")]


def _verdict(result: dict) -> str:
    return result["assessment"]["verdict"]


# Every successful login counts


def test_an_earlier_vpn_login_does_not_hide_a_later_brute_force(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("11:00", ip=VPN), *BRUTE_FORCE], threat_intel=CLEAN)
    result = investigate()
    assert _verdict(result) == "suspicious"
    assert result["assessment"]["escalate"] is True


def test_the_threat_is_confirmed_when_the_hidden_login_reaches_a_sensitive_asset(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[login("11:00", ip=VPN), *BRUTE_FORCE],
        firewall=[finance_access("13:58")],
        threat_intel=CLEAN,
    )
    result = investigate()
    assert _verdict(result) == "confirmed_threat"
    cited = {item["evidence_id"] for item in result["assessment"]["supporting_evidence"]}
    attacker_login = next(
        item["id"]
        for item in result["evidence"]
        if item["raw"]["action"] == "success" and item["raw"]["src_ip"] == ATTACKER
    )
    assert attacker_login in cited


def test_repeated_failures_from_outside_are_not_benign_even_if_they_never_succeed(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=[login("11:00", ip=VPN), *failures(5)], threat_intel=CLEAN)
    assert _verdict(investigate()) == "suspicious"


def test_a_success_with_no_recorded_source_is_not_benign(monkeypatch, tmp_path):
    use_logs(
        monkeypatch, tmp_path, authentication=[login("11:00", ip=VPN), login("13:00", ip="")], threat_intel=CLEAN
    )
    assert _verdict(investigate(src_ip=VPN)) == "suspicious"


def test_brute_force_success_escalates_without_any_other_gap(monkeypatch, tmp_path):
    use_logs(monkeypatch, tmp_path, authentication=BRUTE_FORCE, threat_intel=CLEAN)
    result = investigate()
    assert result["assessment"]["missing_evidence"] == []
    assert result["assessment"]["escalate"] is True


def test_mistyped_password_then_vpn_login_stays_benign(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=[*failures(3, ip=VPN), login("13:50", ip=VPN)],
        firewall=[flow("13:55", dst_ip="10.0.9.9")],
        threat_intel=CLEAN,
    )
    result = investigate(src_ip=VPN)
    assert _verdict(result) == "likely_benign"
    assert result["assessment"]["escalate"] is False


@pytest.mark.parametrize("count,expected", [(2, False), (3, True)])
def test_three_failures_make_an_outside_success_a_compromise(monkeypatch, tmp_path, count, expected):
    use_logs(monkeypatch, tmp_path, authentication=[*failures(count), login("13:56")], threat_intel=CLEAN)
    assert investigate()["assessment"]["escalate"] is expected
