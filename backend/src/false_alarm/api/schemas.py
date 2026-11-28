"""Response models for every API route. The console's TypeScript types are generated from these."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from false_alarm.domain.models import Alert, InvestigationDocument, InvestigationStatus, Severity, Verdict


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FieldMessage(_Model):
    field: str
    message: str


class FieldErrors(_Model):
    """A 422 (or 415) from the API."""

    errors: list[FieldMessage]


class AlertSummary(_Model):
    id: str
    source: str
    name: str
    severity: Severity
    detected_at: str
    username: str | None
    hostname: str | None
    src_ip: str | None
    verdict: Verdict | None
    latest_investigation_id: str | None


class AlertList(_Model):
    alerts: list[AlertSummary]


class AlertView(_Model):
    alert: Alert
    warnings: list[FieldMessage]


class IngestResponse(_Model):
    alert: Alert
    warnings: list[FieldMessage]
    duplicate: bool


class UploadResponse(_Model):
    """One entry per uploaded item: the ingested alert, or the item's field errors."""

    results: list[IngestResponse | FieldErrors]


class ScenarioSummary(_Model):
    id: str
    title: str
    description: str
    expected_verdict: str


class ScenarioList(_Model):
    scenarios: list[ScenarioSummary]


class InvestigationStarted(_Model):
    id: str
    status: Literal["running"]


class InvestigationSummary(_Model):
    id: str
    status: InvestigationStatus
    stop_reason: str | None
    verdict: Verdict | None
    created_at: str
    updated_at: str


class InvestigationList(_Model):
    investigations: list[InvestigationSummary]


# The order the generator writes them in.
PUBLIC_MODELS: tuple[type[BaseModel], ...] = (
    FieldErrors,
    AlertList,
    AlertView,
    IngestResponse,
    UploadResponse,
    ScenarioList,
    InvestigationStarted,
    InvestigationList,
    InvestigationDocument,
)
