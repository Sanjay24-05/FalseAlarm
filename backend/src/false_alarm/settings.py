"""Environment-backed settings. Defaults keep the demo offline."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _number(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    db_path: Path
    scenarios_dir: Path
    llm_enabled: bool
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    max_tool_calls: int
    max_events: int
    max_window_expansions: int
    max_seconds: int
    window_before_minutes: int
    window_after_minutes: int

    def llm_configured(self) -> bool:
        return bool(
            self.llm_enabled
            and self.llm_base_url.strip()
            and self.llm_api_key.strip()
            and self.llm_model.strip()
        )


@lru_cache
def get_settings() -> Settings:
    db_default = REPO_ROOT / "backend" / "data" / "false_alarm.db"
    scenarios_default = REPO_ROOT / "data" / "scenarios"
    return Settings(
        db_path=Path(os.environ.get("FALSE_ALARM_DB_PATH", db_default)),
        scenarios_dir=Path(os.environ.get("FALSE_ALARM_SCENARIOS_DIR", scenarios_default)),
        llm_enabled=_flag("FALSE_ALARM_LLM_ENABLED", False),
        llm_base_url=os.environ.get("FALSE_ALARM_LLM_BASE_URL", ""),
        llm_api_key=os.environ.get("FALSE_ALARM_LLM_API_KEY", ""),
        llm_model=os.environ.get("FALSE_ALARM_LLM_MODEL", ""),
        max_tool_calls=_number("FALSE_ALARM_MAX_TOOL_CALLS", 12),
        max_events=_number("FALSE_ALARM_MAX_EVENTS", 200),
        max_window_expansions=_number("FALSE_ALARM_MAX_WINDOW_EXPANSIONS", 2),
        max_seconds=_number("FALSE_ALARM_MAX_SECONDS", 60),
        window_before_minutes=_number("FALSE_ALARM_WINDOW_BEFORE_MINUTES", 240),
        window_after_minutes=_number("FALSE_ALARM_WINDOW_AFTER_MINUTES", 120),
    )
