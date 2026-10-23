"""Validated planner actions. The tool name must be on the allowlist."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from false_alarm.agent.allowlist import ALLOWED_TOOLS


class ToolAction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    question: str
    question_id: str | None = None

    @field_validator("tool")
    @classmethod
    def known_tool(cls, value: str) -> str:
        if value not in ALLOWED_TOOLS:
            raise ValueError(f"Unknown tool: {value}")
        return value
