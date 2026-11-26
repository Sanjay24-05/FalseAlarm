"""Every shipped scenario reaches its expected verdict through its expected playbook."""

import json

import pytest

from false_alarm.reports import EVIDENCE_ID_RE, SECTION_KEYS
from false_alarm.service import load_scenario, run_investigation
from false_alarm.settings import get_settings

PLAYBOOKS = ("authentication", "malware", "outbound", "generic")
SCENARIO_DIRS = sorted(path for path in get_settings().scenarios_dir.iterdir() if (path / "meta.json").exists())


def _meta(directory) -> dict:
    return json.loads((directory / "meta.json").read_text(encoding="utf-8"))


def test_each_playbook_has_a_malicious_and_a_benign_scenario():
    covered = {(_meta(path).get("expected_playbook"), _meta(path)["expected_verdict"]) for path in SCENARIO_DIRS}
    for playbook in PLAYBOOKS:
        assert (playbook, "confirmed_threat") in covered, playbook
        assert (playbook, "likely_benign") in covered, playbook


@pytest.mark.parametrize("directory", SCENARIO_DIRS, ids=lambda path: path.name)
def test_scenario_reaches_its_expected_verdict(directory):
    meta = _meta(directory)
    loaded = load_scenario(meta["id"])
    assert loaded.errors == [] and loaded.duplicate is False
    result = run_investigation(loaded.alert["id"])
    assessment = result["assessment"]

    assert result["status"] == "completed"
    assert assessment["verdict"] == meta["expected_verdict"]
    assert assessment["escalate"] is (meta["expected_verdict"] == "confirmed_threat")
    playbook = next(entry["summary"] for entry in result["audit"] if entry["kind"] == "playbook")
    assert playbook == f"Selected the {meta['expected_playbook']} playbook"

    known = {item["id"] for item in result["evidence"]}
    blob = "\n".join(result["report"].values())
    assert set(result["report"]) == set(SECTION_KEYS)
    assert "Deterministic template." not in blob
    assert set(EVIDENCE_ID_RE.findall(blob)) <= known
    for event in result["timeline"]:
        assert set(event["evidence_ids"]) <= known
