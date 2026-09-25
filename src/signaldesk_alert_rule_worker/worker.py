from __future__ import annotations
import logging
from collections.abc import Callable, Mapping
from signaldesk_contracts import DiagnosticTerminalV2
from signaldesk_streams_kit import DeadLetterReason, ack_if_owned, dead_letter_if_owned, parse_stream_event
from signaldesk_streams_kit import reclaim_stale_pending
import httpx
from .clients import ControlClient, ImmutableNotificationResponse, MonitorClient, NotificationClient

log = logging.getLogger("signaldesk_alert_rule_worker")
ACK = "ack"; PENDING = "pending"; DLQ = "dlq"

class AlertRuleWorker:
    def __init__(self, control: ControlClient, monitor: MonitorClient, notification: NotificationClient, *, ack: Callable[[str], bool] | None = None, dlq: Callable[[str, DeadLetterReason, Mapping], bool] | None = None):
        self.control, self.monitor, self.notification, self._ack, self._dlq = control, monitor, notification, ack, dlq

    def close(self) -> None:
        self.control.close()
        self.monitor.close()
        self.notification.close()

    def process(self, raw: Mapping[str, str | bytes], *, message_id: str = "test", consumer: str = "test", redis=None) -> str:
        try:
            event = parse_stream_event(raw)
            if not isinstance(event, DiagnosticTerminalV2):
                return self._dead(message_id, consumer, raw, DeadLetterReason.UNSUPPORTED_EVENT, redis)
            terminal = self.control.terminal(event.diagnostic_job_id)
            if terminal is None: return ACK
            if (terminal.diagnostic_job_id != event.diagnostic_job_id or terminal.organization_id != event.organization_id or terminal.correlation_id != event.correlation_id or terminal.status != event.status):
                return self._dead(message_id, consumer, raw, DeadLetterReason.TENANT_MISMATCH, redis)
            # The stream scope is only a consistency assertion.  All
            # downstream decisions use terminal fields fetched from control.
            resolution = self.monitor.resolve(terminal.diagnostic_job_id, terminal.organization_id, terminal.status)
            if resolution is None: return ACK
            if resolution.organization_id != terminal.organization_id or resolution.creator_id != terminal.requested_by_user_id:
                return self._dead(message_id, consumer, raw, DeadLetterReason.TENANT_MISMATCH, redis)
            matched = resolution.alert_on_failure and (terminal.status == "failed" or terminal.outcome in {"error", "blocked"})
            if matched: self.notification.create(terminal=terminal, resolution=resolution)
            return ACK
        except ImmutableNotificationResponse:
            return self._dead(message_id, consumer, raw, DeadLetterReason.IMPOSSIBLE_STATE, redis)
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as error:
            if isinstance(error, httpx.HTTPStatusError) and error.response.status_code in (401, 403):
                log.error("outcome=readiness_failure")
            if isinstance(error, httpx.HTTPStatusError) and error.response.status_code == 409:
                return self._dead(message_id, consumer, raw, DeadLetterReason.IMPOSSIBLE_STATE, redis)
            return PENDING
        except (ValueError, TypeError):
            return self._dead(message_id, consumer, raw, DeadLetterReason.MALFORMED_EVENT, redis)

    def _dead(self, message_id, consumer, raw, reason, redis):
        if self._dlq: return DLQ if self._dlq(message_id, reason, raw) else PENDING
        if redis is None: return DLQ
        return DLQ if dead_letter_if_owned(redis, "signaldesk:diagnostic-terminals", "alert-rule-workers", message_id, consumer, "signaldesk:diagnostic-terminals:dlq", reason, raw) else PENDING

    def run_once(self, redis, config) -> bool:
        records = redis.xreadgroup(config.group, config.consumer, {config.stream: ">"}, count=1, block=1)
        if not records: return False
        for _, entries in records:
            for message_id, raw in entries:
                result = self.process(raw, message_id=str(message_id), consumer=config.consumer, redis=redis)
                if result == ACK: ack_if_owned(redis, config.stream, config.group, str(message_id), config.consumer)
        return True
