"""File-backed scenario catalog: org context, baselines, and scenario metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from false_alarm.errors import ScenarioNotFound
from false_alarm.settings import get_settings


def scenario_dirs(root: Path | None = None) -> list[Path]:
    base = root or get_settings().scenarios_dir
    if not base.exists():
        return []
    return sorted(
        (child for child in base.iterdir() if child.is_dir() and not child.name.startswith(".")),
        key=lambda path: path.name,
    )


@dataclass
class Catalog:
    assets: list[dict] = field(default_factory=list)
    corporate_vpn_ranges: list[str] = field(default_factory=list)
    known_good_ranges: list[str] = field(default_factory=list)
    scanner_ranges: list[str] = field(default_factory=list)
    baselines: dict[str, dict] = field(default_factory=dict)

    def baseline_for(self, username: str | None) -> dict:
        if not username:
            return {}
        return self.baselines.get(username.casefold(), {})

    def match_asset(self, ip: str | None, host: str | None) -> dict | None:
        for asset in self.assets:
            if ip and asset.get("ip") == ip:
                return asset
            hostname = asset.get("hostname")
            if host and isinstance(hostname, str) and hostname.casefold() == host.casefold():
                return asset
        return None


def _extend(target: list[str], values: object) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if isinstance(value, str) and value not in target:
            target.append(value)


@lru_cache
def load_catalog(root: str, single: bool = False) -> Catalog:
    """Org context from context.json in each scenario directory under root, or in root itself when single."""
    catalog = Catalog()
    assets_by_ip: dict[str, dict] = {}
    for directory in [Path(root)] if single else scenario_dirs(Path(root)):
        path = directory / "context.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        for asset in data.get("assets") or []:
            if isinstance(asset, dict) and isinstance(asset.get("ip"), str):
                assets_by_ip[asset["ip"]] = asset
        _extend(catalog.corporate_vpn_ranges, data.get("corporate_vpn_ranges"))
        _extend(catalog.known_good_ranges, data.get("known_good_ranges"))
        _extend(catalog.scanner_ranges, data.get("scanner_ranges"))
        baselines = data.get("baselines") or {}
        if isinstance(baselines, dict):
            for username, baseline in baselines.items():
                if isinstance(username, str) and isinstance(baseline, dict):
                    slot = catalog.baselines.setdefault(username.casefold(), {})
                    slot.update(baseline)
    catalog.assets = list(assets_by_ip.values())
    return catalog


def get_catalog() -> Catalog:
    settings = get_settings()
    if settings.connector == "jsonl" and settings.logs_dir is not None:
        return load_catalog(str(settings.logs_dir), single=True)
    return load_catalog(str(settings.scenarios_dir))


def list_scenarios() -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for directory in scenario_dirs():
        meta_path = directory / "meta.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        items.append(
            {
                "id": str(meta["id"]),
                "title": str(meta["title"]),
                "description": str(meta["description"]),
                "expected_verdict": str(meta["expected_verdict"]),
            }
        )
    return sorted(items, key=lambda item: item["id"])


def load_scenario_payload(scenario_id: str) -> dict:
    for directory in scenario_dirs():
        meta_path = directory / "meta.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if str(meta.get("id")) != scenario_id and directory.name != scenario_id:
            continue
        alert_path = directory / "alert.json"
        if not alert_path.exists():
            break
        payload = json.loads(alert_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ScenarioNotFound(scenario_id)
        return payload
    raise ScenarioNotFound(scenario_id)
