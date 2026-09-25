import os
import json
import time
from uuid import uuid4

import pytest
import redis

from signaldesk_alert_rule_worker.clients import Terminal
from signaldesk_alert_rule_worker.worker import AlertRuleWorker
from signaldesk_streams_kit import DeadLetterReason, StreamConsumerConfig, ack_if_owned, dead_letter_if_owned, ensure_consumer_group, process_consumer_name, reclaim_stale_pending


@pytest.mark.integration
def test_real_redis_fenced_dlq_contains_identifiers_only():
    url = os.getenv("SIGNALDESK_TEST_REDIS_URL")
    if not url:
        pytest.skip("set SIGNALDESK_TEST_REDIS_URL for real Redis integration")
    client = redis.Redis.from_url(url, decode_responses=False)
    client.ping()
    suffix = uuid4().hex
    config = StreamConsumerConfig(stream=f"signaldesk:test:{suffix}", group="alert-rule-workers", dead_letter_stream=f"signaldesk:test:{suffix}:dlq", consumer=process_consumer_name("integration"))
    assert ensure_consumer_group(client, config.stream, config.group) is True
    assert ensure_consumer_group(client, config.stream, config.group) is False
    event_id = str(uuid4())
    message_id = client.xadd(config.stream, {"event_id": event_id, "event": "not-a-contract"})
    entry = client.xreadgroup(config.group, config.consumer, {config.stream: ">"}, count=1)[0][1][0]
    assert dead_letter_if_owned(client, config.stream, config.group, entry[0], config.consumer, config.dead_letter_stream, DeadLetterReason.MALFORMED_EVENT, entry[1])
    fields = dict(client.xrange(config.dead_letter_stream)[0][1])
    assert b"event" not in fields
    assert ack_if_owned(client, config.stream, config.group, message_id.decode(), config.consumer) is False

    reclaim_id = client.xadd(config.stream, {"event_id": str(uuid4()), "event": "not-a-contract"})
    client.xreadgroup(config.group, config.consumer, {config.stream: ">"}, count=1)
    time.sleep(0.02)
    reclaimed = reclaim_stale_pending(client, config.stream, config.group, process_consumer_name("reclaimer"), min_idle_ms=1)
    assert any(entry.id == reclaim_id.decode() for entry in reclaimed.entries)


@pytest.mark.integration
def test_real_redis_forged_terminal_is_fenced_to_sanitized_dlq_without_mutation():
    url = os.getenv("SIGNALDESK_TEST_REDIS_URL")
    if not url:
        pytest.skip("set SIGNALDESK_TEST_REDIS_URL for real Redis integration")
    client = redis.Redis.from_url(url, decode_responses=False)
    suffix = uuid4().hex
    # The worker topology is deliberately fixed by its deployment contract.
    config = StreamConsumerConfig(stream="signaldesk:diagnostic-terminals", group="alert-rule-workers", dead_letter_stream="signaldesk:diagnostic-terminals:dlq", consumer=process_consumer_name(f"integration-{suffix}"))
    ensure_consumer_group(client, config.stream, config.group)
    event_id, job_id, forged_org, actual_org, correlation, user_id = (uuid4() for _ in range(6))
    event = {"schema_version": 1, "event_type": "diagnostic.terminal.v2", "event_id": str(event_id), "occurred_at": "2026-01-01T00:00:00+00:00", "correlation_id": str(correlation), "organization_id": str(forged_org), "diagnostic_job_id": str(job_id), "status": "failed"}
    client.xadd(config.stream, {"event": json.dumps(event), "event_id": str(event_id)})
    message_id, raw = client.xreadgroup(config.group, config.consumer, {config.stream: ">"}, count=1)[0][1][0]

    class Control:
        def terminal(self, _):
            return Terminal(diagnostic_job_id=job_id, organization_id=actual_org, requested_by_user_id=user_id, correlation_id=correlation, status="failed", outcome=None, error_code="probe_failed")

        def close(self): pass

    class NoBusinessMutation:
        called = False

        def resolve(self, *_args):
            self.called = True
            raise AssertionError("forged event reached monitor resolution")

        def close(self): pass

    monitor = NoBusinessMutation()
    worker = AlertRuleWorker(Control(), monitor, NoBusinessMutation())
    assert worker.process(raw, message_id=message_id.decode(), consumer=config.consumer, redis=client) == "dlq"
    assert monitor.called is False
    dlq = dict(client.xrange(config.dead_letter_stream)[0][1])
    assert dlq[b"reason_code"] == b"tenant_mismatch"
    assert b"event" not in dlq
