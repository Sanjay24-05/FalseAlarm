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


# Attribution

ACCESS = [login("13:50")]


def _investigate(monkeypatch, tmp_path, authentication=ACCESS, **logs):
    use_logs(monkeypatch, tmp_path, authentication=authentication, threat_intel=CLEAN, **logs)
    return investigate()


def test_the_users_own_access_after_login_is_a_threat(monkeypatch, tmp_path):
    assert _verdict(_investigate(monkeypatch, tmp_path, firewall=[finance_access("13:58")])) == "confirmed_threat"


@pytest.mark.parametrize(
    "record",
    [
        finance_access("13:58", user="backup_svc"),
        finance_access("10:30"),
        finance_access("13:58", action="deny", bytes=0),
        finance_access("13:58", action="Blocked", bytes=0),
        flow("13:58", user="alice", dst_ip="91.2.3.4", direction="outbound", bytes=900_000_000),
        flow("10:30", dst_ip="91.2.3.4", direction="outbound", bytes=900_000_000),
        flow("13:58", dst_ip="91.2.3.4", direction="outbound", bytes=900_000_000, action="drop"),
    ],
    ids=["other-user", "before-login", "deny", "blocked", "other-user-out", "before-login-out", "dropped-out"],
)
def test_activity_that_is_not_the_users_later_action_is_not_confirmed(monkeypatch, tmp_path, record):
    result = _investigate(monkeypatch, tmp_path, firewall=[record])
    assert _verdict(result) == "suspicious"
    assert result["assessment"]["severity"] == "medium"
    assert any("not attributed" in gap for gap in result["assessment"]["missing_evidence"])
    assert result["assessment"]["escalate"] is True


@pytest.mark.parametrize("record", [finance_access("13:58", user="backup_svc"), finance_access("10:30")])
def test_unattributed_harm_still_blocks_benign(monkeypatch, tmp_path, record):
    use_logs(monkeypatch, tmp_path, authentication=[login("13:00", ip=VPN)], firewall=[record], threat_intel=CLEAN)
    assert _verdict(investigate(src_ip=VPN)) == "suspicious"


MALWARE = {"action": "malware_detected", "severity": "critical", "timestamp": "2026-04-12T13:58:00Z"}


@pytest.mark.parametrize("account", ["SYSTEM", "NT AUTHORITY\SYSTEM", "ws-bob$", "root", None])
def test_machine_account_activity_on_the_alert_host_is_attributed(monkeypatch, tmp_path, account):
    result = _investigate(monkeypatch, tmp_path, endpoint=[{**MALWARE, "username": account, "hostname": "ws-bob"}])
    assert _verdict(result) == "confirmed_threat"


def test_userless_firewall_traffic_from_the_login_source_is_attributed(monkeypatch, tmp_path):
    use_logs(
        monkeypatch,
        tmp_path,
        authentication=ACCESS,
        firewall=[finance_access("13:58", user="", host="", src_ip=ATTACKER)],
        threat_intel=CLEAN,
    )
    assert _verdict(investigate(username=None, hostname=None)) == "confirmed_threat"


def test_username_case_does_not_matter(monkeypatch, tmp_path):
    assert _verdict(_investigate(monkeypatch, tmp_path, firewall=[finance_access("13:58", user="BOB")])) == (
        "confirmed_threat"
    )


def test_another_users_related_alert_is_not_confirmed(monkeypatch, tmp_path):
    record = {"timestamp": "2026-04-12T13:58:00Z", "username": "alice", "hostname": "WS-BOB", "name": "x", "severity": "high"}
    assert _verdict(_investigate(monkeypatch, tmp_path, related_alerts=[record])) == "suspicious"
