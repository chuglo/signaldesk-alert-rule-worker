from __future__ import annotations

from typing import Any, Literal
from uuid import UUID
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ACTOR = "alert-rule-worker"

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class Terminal(Strict):
    diagnostic_job_id: UUID = Field(strict=False)
    organization_id: UUID = Field(strict=False)
    requested_by_user_id: UUID = Field(strict=False)
    correlation_id: UUID = Field(strict=False)
    status: Literal["completed", "failed"]
    outcome: Literal["reachable", "error", "blocked"] | None
    error_code: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

class Resolution(Strict):
    run_id: UUID = Field(strict=False)
    monitor_id: UUID = Field(strict=False)
    organization_id: UUID = Field(strict=False)
    creator_id: UUID = Field(strict=False)
    alert_on_failure: bool


def _canonical_uuid(value: Any) -> UUID:
    """Accept only notification-api's canonical JSON UUID representation."""
    if not isinstance(value, str):
        raise ValueError("UUID must be a JSON string")
    try:
        parsed = UUID(value)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid UUID") from error
    if str(parsed) != value:
        raise ValueError("UUID is not canonical")
    return parsed


class DiagnosticAlertTemplateData(Strict):
    monitor_id: UUID = Field(strict=False)
    monitor_run_id: UUID = Field(strict=False)
    diagnostic_job_id: UUID = Field(strict=False)
    status: Literal["completed", "failed"]
    outcome: Literal["reachable", "error", "blocked"] | None
    error_code: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

    @field_validator("monitor_id", "monitor_run_id", "diagnostic_job_id", mode="before")
    @classmethod
    def canonical_identifiers(cls, value: Any) -> UUID:
        return _canonical_uuid(value)


class Notification(Strict):
    """The closed notification-api create response contract."""
    id: UUID = Field(strict=False)
    organization_id: UUID = Field(strict=False)
    correlation_id: UUID = Field(strict=False)
    state: Literal["pending"]
    monitor_id: UUID = Field(strict=False)
    monitor_run_id: UUID = Field(strict=False)
    diagnostic_job_id: UUID = Field(strict=False)
    requested_by_user_id: UUID = Field(strict=False)
    template_name: Literal["diagnostic_alert"]
    template_data: DiagnosticAlertTemplateData
    email_delivery_id: None
    failure_code: None
    lease_generation: Literal[0]
    lease_expires_at: None

    @field_validator("id", "organization_id", "correlation_id", "monitor_id", "monitor_run_id", "diagnostic_job_id", "requested_by_user_id", mode="before")
    @classmethod
    def canonical_identifiers(cls, value: Any) -> UUID:
        return _canonical_uuid(value)


class ImmutableNotificationResponse(ValueError):
    """A successful HTTP response that cannot represent this create request."""

def headers(credential: str) -> dict[str, str]:
    return {"X-SignalDesk-Service-Actor": ACTOR, "X-SignalDesk-Service-Credential": credential}

class _Client:
    def __init__(self, base_url: str, credential: str, *, client: httpx.Client | None = None, timeout: httpx.Timeout | None = None):
        self.client = client or httpx.Client(base_url=base_url, timeout=timeout or httpx.Timeout(5, connect=2))
        self.headers = headers(credential)

    def close(self) -> None:
        self.client.close()

class ControlClient(_Client):
    def terminal(self, diagnostic_id: UUID) -> Terminal | None:
        response = self.client.get(f"/internal/alert-rule/diagnostics/{diagnostic_id}/terminal", headers=self.headers)
        if response.status_code == 404: return None
        response.raise_for_status()
        return Terminal.model_validate(response.json())

class MonitorClient(_Client):
    def resolve(self, diagnostic_id: UUID, organization_id: UUID, status: str) -> Resolution | None:
        response = self.client.post("/internal/alert-rules/resolve", headers=self.headers, json={"diagnostic_job_id": str(diagnostic_id), "organization_id": str(organization_id), "status": status})
        if response.status_code == 404: return None
        response.raise_for_status()
        return Resolution.model_validate(response.json())

class NotificationClient(_Client):
    def create(self, *, terminal: Terminal, resolution: Resolution) -> Notification:
        data = {"monitor_id": str(resolution.monitor_id), "monitor_run_id": str(resolution.run_id), "diagnostic_job_id": str(terminal.diagnostic_job_id), "status": terminal.status, "outcome": terminal.outcome, "error_code": terminal.error_code}
        response = self.client.post("/internal/notifications/alerts", headers=self.headers, json={"organization_id": str(terminal.organization_id), "correlation_id": str(terminal.correlation_id), "monitor_id": str(resolution.monitor_id), "monitor_run_id": str(resolution.run_id), "diagnostic_job_id": str(terminal.diagnostic_job_id), "requested_by_user_id": str(terminal.requested_by_user_id), "template_name": "diagnostic_alert", "template_data": data})
        response.raise_for_status()
        try:
            notification = Notification.model_validate(response.json())
        except (TypeError, ValueError) as error:
            raise ImmutableNotificationResponse("notification create response violates its immutable contract") from error
        expected_data = DiagnosticAlertTemplateData.model_validate(data)
        if (
            notification.organization_id != terminal.organization_id
            or notification.correlation_id != terminal.correlation_id
            or notification.monitor_id != resolution.monitor_id
            or notification.monitor_run_id != resolution.run_id
            or notification.diagnostic_job_id != terminal.diagnostic_job_id
            or notification.requested_by_user_id != terminal.requested_by_user_id
            or notification.template_data != expected_data
        ):
            raise ImmutableNotificationResponse("notification create response does not match the immutable request")
        return notification
