import json
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from pydantic import RedisDsn

from signaldesk_alert_rule_worker.clients import (
    ControlClient,
    ImmutableNotificationResponse,
    MonitorClient,
    NotificationClient,
    Resolution,
    Terminal,
)
from signaldesk_alert_rule_worker.health import readiness
from signaldesk_alert_rule_worker.worker import AlertRuleWorker


def test_cli_converts_redis_dsn_before_redis_construction(monkeypatch):
    from signaldesk_alert_rule_worker import cli

    class Settings:
        control_api_url = "https://control.test"
        monitor_api_url = "https://monitor.test"
        notification_api_url = "https://notification.test"
        redis_url = RedisDsn("redis://localhost:6379/0")
        control_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "c" * 32})()
        monitor_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "m" * 32})()
        notification_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "n" * 32})()
        request_connect_timeout_seconds = request_read_timeout_seconds = request_write_timeout_seconds = request_pool_timeout_seconds = 1
        reclaim_idle_seconds = poll_interval_seconds = 1
        service_name = "alert-rule-worker-test"

    class Redis:
        def close(self):
            return None

    class Worker:
        def __init__(self, *_args, **_kwargs):
            pass

        def run_once(self, *_args, **_kwargs):
            return None

        def close(self):
            return None

    monkeypatch.setattr(cli, "Settings", lambda: Settings())
    monkeypatch.setattr(cli, "ensure_consumer_group", lambda *_args: None)
    monkeypatch.setattr(cli, "reclaim_stale_pending", lambda *_args, **_kwargs: type("Result", (), {"entries": ()})())
    monkeypatch.setattr(cli, "AlertRuleWorker", Worker)
    monkeypatch.setattr(cli.redis.Redis, "from_url", lambda url, **_kwargs: (_ for _ in ()).throw(AttributeError("RedisDsn has no attribute startswith")) if isinstance(url, RedisDsn) else Redis())

    assert cli.main(["--once"]) == 0


def notification_response(*, terminal, resolution, **overrides):
    value = {
        "id": str(uuid4()),
        "organization_id": str(terminal.organization_id),
        "correlation_id": str(terminal.correlation_id),
        "state": "pending",
        "monitor_id": str(resolution.monitor_id),
        "monitor_run_id": str(resolution.run_id),
        "diagnostic_job_id": str(terminal.diagnostic_job_id),
        "requested_by_user_id": str(terminal.requested_by_user_id),
        "template_name": "diagnostic_alert",
        "template_data": {
            "monitor_id": str(resolution.monitor_id),
            "monitor_run_id": str(resolution.run_id),
            "diagnostic_job_id": str(terminal.diagnostic_job_id),
            "status": terminal.status,
            "outcome": terminal.outcome,
            "error_code": terminal.error_code,
        },
        "email_delivery_id": None,
        "failure_code": None,
        "lease_generation": 0,
        "lease_expires_at": None,
    }
    value.update(overrides)
    return value


def test_failed_terminal_creates_one_notification_with_authoritative_headers_and_fields():
    event_id, diagnostic_id, org, correlation, creator = (uuid4() for _ in range(5))
    seen = []

    run_id, monitor_id = uuid4(), uuid4()
    terminal = Terminal(diagnostic_job_id=diagnostic_id, organization_id=org, requested_by_user_id=creator, correlation_id=correlation, status="failed", outcome=None, error_code="probe_failed")
    resolution = Resolution(run_id=run_id, monitor_id=monitor_id, organization_id=org, creator_id=creator, alert_on_failure=True)

    def handler(request):
        seen.append(request)
        if request.url.host == "control.test":
            return httpx.Response(200, json={"diagnostic_job_id": str(diagnostic_id), "organization_id": str(org), "requested_by_user_id": str(creator), "correlation_id": str(correlation), "status": "failed", "outcome": None, "error_code": "probe_failed"})
        if request.url.host == "monitor.test":
            return httpx.Response(200, json=resolution.model_dump(mode="json"))
        return httpx.Response(201, json=notification_response(terminal=terminal, resolution=resolution))

    clients = []
    for host in ("control.test", "monitor.test", "notification.test"):
        clients.append(httpx.Client(transport=httpx.MockTransport(handler), base_url=f"https://{host}"))
    control, monitor, notification = (ControlClient("https://control.test", "c" * 32, client=clients[0]), MonitorClient("https://monitor.test", "m" * 32, client=clients[1]), NotificationClient("https://notification.test", "n" * 32, client=clients[2]))
    worker = AlertRuleWorker(control, monitor, notification)
    raw = {"event": '{"schema_version":1,"event_type":"diagnostic.terminal.v2","event_id":"%s","occurred_at":"%s","correlation_id":"%s","organization_id":"%s","diagnostic_job_id":"%s","status":"failed"}' % (event_id, datetime.now(timezone.utc).isoformat(), correlation, org, diagnostic_id), "event_id": str(event_id)}
    result = worker.process(raw)
    assert result == "ack"
    assert seen[0].headers["X-SignalDesk-Service-Actor"] == "alert-rule-worker"
    assert seen[1].headers["X-SignalDesk-Service-Actor"] == "alert-rule-worker"
    assert seen[2].headers["X-SignalDesk-Service-Actor"] == "alert-rule-worker"
    assert seen[0].headers["X-SignalDesk-Service-Credential"] == "c" * 32
    assert seen[1].headers["X-SignalDesk-Service-Credential"] == "m" * 32
    assert seen[2].headers["X-SignalDesk-Service-Credential"] == "n" * 32


def test_notification_request_is_fixed_diagnostic_alert_without_recipient_data():
    diagnostic_id, org, correlation, creator, run_id, monitor_id = (uuid4() for _ in range(6))
    captured = {}

    def handler(request):
        if request.url.host == "control.test":
            return httpx.Response(200, json={"diagnostic_job_id": str(diagnostic_id), "organization_id": str(org), "requested_by_user_id": str(creator), "correlation_id": str(correlation), "status": "completed", "outcome": "blocked", "error_code": "policy_blocked"})
        if request.url.host == "monitor.test":
            return httpx.Response(200, json={"run_id": str(run_id), "monitor_id": str(monitor_id), "organization_id": str(org), "creator_id": str(creator), "alert_on_failure": True})
        captured.update(json.loads(request.content))
        terminal = Terminal(diagnostic_job_id=diagnostic_id, organization_id=org, requested_by_user_id=creator, correlation_id=correlation, status="completed", outcome="blocked", error_code="policy_blocked")
        resolution = Resolution(run_id=run_id, monitor_id=monitor_id, organization_id=org, creator_id=creator, alert_on_failure=True)
        return httpx.Response(201, json=notification_response(terminal=terminal, resolution=resolution))

    clients = [httpx.Client(transport=httpx.MockTransport(handler), base_url=f"https://{host}") for host in ("control.test", "monitor.test", "notification.test")]
    worker = AlertRuleWorker(ControlClient("https://control.test", "c" * 32, client=clients[0]), MonitorClient("https://monitor.test", "m" * 32, client=clients[1]), NotificationClient("https://notification.test", "n" * 32, client=clients[2]))
    raw = {"event": '{{"schema_version":1,"event_type":"diagnostic.terminal.v2","event_id":"{event_id}","occurred_at":"{occurred_at}","correlation_id":"{correlation}","organization_id":"{org}","diagnostic_job_id":"{diagnostic_id}","status":"completed"}}'.format(event_id=uuid4(), occurred_at=datetime.now(timezone.utc).isoformat(), correlation=correlation, org=org, diagnostic_id=diagnostic_id), "event_id": str(uuid4())}
    # The envelope event_id is deliberately corrected below to keep the event
    # canonical while retaining a compact literal above.
    payload = json.loads(raw["event"])
    raw["event_id"] = payload["event_id"]

    assert worker.process(raw) == "ack"
    assert captured["template_name"] == "diagnostic_alert"
    assert set(captured) == {"organization_id", "correlation_id", "monitor_id", "monitor_run_id", "diagnostic_job_id", "requested_by_user_id", "template_name", "template_data"}
    assert "recipient" not in repr(captured).lower()


def test_notification_client_accepts_exact_notification_api_created_response():
    diagnostic_id, org, correlation, creator, run_id, monitor_id = (uuid4() for _ in range(6))
    terminal = Terminal(diagnostic_job_id=diagnostic_id, organization_id=org, requested_by_user_id=creator, correlation_id=correlation, status="failed", outcome=None, error_code="probe_failed")
    resolution = Resolution(run_id=run_id, monitor_id=monitor_id, organization_id=org, creator_id=creator, alert_on_failure=True)
    client = NotificationClient("https://notification.test", "n" * 32, client=httpx.Client(base_url="https://notification.test", transport=httpx.MockTransport(lambda _: httpx.Response(201, json=notification_response(terminal=terminal, resolution=resolution)))))

    assert client.create(terminal=terminal, resolution=resolution).organization_id == org


@pytest.mark.parametrize("mutate", [
    lambda response: {"id": response["id"]},
    lambda response: response | {"unexpected": "field"},
    lambda response: response | {"organization_id": str(uuid4())},
    lambda response: response | {"correlation_id": str(uuid4())},
    lambda response: response | {"template_name": "other"},
    lambda response: response | {"template_data": response["template_data"] | {"status": "completed"}},
    lambda response: response | {"id": response["id"].upper()},
    lambda response: response | {"lease_generation": 1},
])
def test_notification_client_rejects_id_only_extra_and_conflicting_create_responses(mutate):
    diagnostic_id, org, correlation, creator, run_id, monitor_id = (uuid4() for _ in range(6))
    terminal = Terminal(diagnostic_job_id=diagnostic_id, organization_id=org, requested_by_user_id=creator, correlation_id=correlation, status="failed", outcome=None, error_code="probe_failed")
    resolution = Resolution(run_id=run_id, monitor_id=monitor_id, organization_id=org, creator_id=creator, alert_on_failure=True)
    body = mutate(notification_response(terminal=terminal, resolution=resolution))
    client = NotificationClient("https://notification.test", "n" * 32, client=httpx.Client(base_url="https://notification.test", transport=httpx.MockTransport(lambda _: httpx.Response(201, json=body))))

    with pytest.raises(ImmutableNotificationResponse):
        client.create(terminal=terminal, resolution=resolution)


@pytest.mark.parametrize("mutate", [
    lambda response: {"id": response["id"]},
    lambda response: response | {"unexpected": "field"},
    lambda response: response | {"organization_id": str(uuid4())},
    lambda response: response | {"correlation_id": str(uuid4())},
    lambda response: response | {"template_data": response["template_data"] | {"status": "completed"}},
])
def test_worker_dlqs_immutable_notification_response_conflict_instead_of_acking(mutate):
    event_id, diagnostic_id, org, correlation, creator, run_id, monitor_id = (uuid4() for _ in range(7))
    terminal = Terminal(diagnostic_job_id=diagnostic_id, organization_id=org, requested_by_user_id=creator, correlation_id=correlation, status="failed", outcome=None, error_code="probe_failed")
    resolution = Resolution(run_id=run_id, monitor_id=monitor_id, organization_id=org, creator_id=creator, alert_on_failure=True)

    def handler(request):
        if request.url.host == "control.test": return httpx.Response(200, json=terminal.model_dump(mode="json"))
        if request.url.host == "monitor.test": return httpx.Response(200, json=resolution.model_dump(mode="json"))
        return httpx.Response(201, json=mutate(notification_response(terminal=terminal, resolution=resolution)))

    clients = [httpx.Client(transport=httpx.MockTransport(handler), base_url=f"https://{host}") for host in ("control.test", "monitor.test", "notification.test")]
    dead = []
    worker = AlertRuleWorker(ControlClient("https://control.test", "c" * 32, client=clients[0]), MonitorClient("https://monitor.test", "m" * 32, client=clients[1]), NotificationClient("https://notification.test", "n" * 32, client=clients[2]), dlq=lambda *_args: dead.append(_args) or True)
    raw = {"event": '{"schema_version":1,"event_type":"diagnostic.terminal.v2","event_id":"%s","occurred_at":"%s","correlation_id":"%s","organization_id":"%s","diagnostic_job_id":"%s","status":"failed"}' % (event_id, datetime.now(timezone.utc).isoformat(), correlation, org, diagnostic_id), "event_id": str(event_id)}

    assert worker.process(raw) == "dlq"
    assert dead[0][1].value == "impossible_state"


def test_reclaimed_entry_uses_fenced_ack(monkeypatch):
    from signaldesk_alert_rule_worker import cli

    calls = []

    class Redis:
        def xreadgroup(self, *_args, **_kwargs):
            return []

        def close(self):
            return None

    class Settings:
        control_api_url = "https://control.test"
        monitor_api_url = "https://monitor.test"
        notification_api_url = "https://notification.test"
        redis_url = "redis://localhost:6379/0"
        control_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "c" * 32})()
        monitor_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "m" * 32})()
        notification_api_credential = type("Secret", (), {"get_secret_value": lambda _self: "n" * 32})()
        request_connect_timeout_seconds = request_read_timeout_seconds = request_write_timeout_seconds = request_pool_timeout_seconds = 1
        reclaim_idle_seconds = poll_interval_seconds = 1
        service_name = "alert-rule-worker-test"

    entry = type("Entry", (), {"id": "1-0", "fields": {"event": "{}", "event_id": str(uuid4())}})()
    monkeypatch.setattr(cli, "Settings", lambda: Settings())
    monkeypatch.setattr(cli.redis.Redis, "from_url", lambda *_args, **_kwargs: Redis())
    monkeypatch.setattr(cli, "ensure_consumer_group", lambda *_args: None)
    monkeypatch.setattr(cli, "reclaim_stale_pending", lambda *_args, **_kwargs: type("Result", (), {"entries": (entry,)})())
    monkeypatch.setattr(cli.AlertRuleWorker, "process", lambda *_args, **_kwargs: "ack")
    monkeypatch.setattr(cli, "ack_if_owned", lambda *_args: calls.append(_args) or True)

    assert cli.main(["--once"]) == 0
    assert len(calls) == 1


def test_readiness_requires_readyz_not_liveness():
    def handler(request):
        return httpx.Response(503 if request.url.path == "/readyz" else 200)

    assert readiness(("https://control.test",), timeout=httpx.Timeout(1), client=httpx.Client(transport=httpx.MockTransport(handler))) is False
