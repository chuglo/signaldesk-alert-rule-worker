from __future__ import annotations
import argparse, signal, time, redis, httpx
from signaldesk_streams_kit import ack_if_owned, reclaim_stale_pending, StreamConsumerConfig, ensure_consumer_group, process_consumer_name
from .clients import ControlClient, MonitorClient, NotificationClient
from .settings import Settings
from .worker import AlertRuleWorker
from .health import readiness
def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--once",action="store_true"); p.add_argument("--ready",action="store_true"); a=p.parse_args(argv)
    try: s=Settings()
    except Exception: return 2
    timeout=httpx.Timeout(connect=s.request_connect_timeout_seconds, read=s.request_read_timeout_seconds, write=s.request_write_timeout_seconds, pool=s.request_pool_timeout_seconds)
    if a.ready:
        if not readiness((str(s.control_api_url), str(s.monitor_api_url), str(s.notification_api_url)), timeout=timeout): return 1
        try:
            r = redis.Redis.from_url(str(s.redis_url), decode_responses=False, socket_connect_timeout=s.request_connect_timeout_seconds, socket_timeout=s.request_read_timeout_seconds)
            r.ping(); r.close()
        except redis.exceptions.RedisError: return 1
        return 0
    r=redis.Redis.from_url(str(s.redis_url), decode_responses=False, socket_connect_timeout=s.request_connect_timeout_seconds, socket_timeout=s.request_read_timeout_seconds); consumer=process_consumer_name(s.service_name)
    config=StreamConsumerConfig(stream="signaldesk:diagnostic-terminals",group="alert-rule-workers",dead_letter_stream="signaldesk:diagnostic-terminals:dlq",consumer=consumer); ensure_consumer_group(r,config.stream,config.group)
    w=AlertRuleWorker(ControlClient(str(s.control_api_url),s.control_api_credential.get_secret_value(),timeout=timeout),MonitorClient(str(s.monitor_api_url),s.monitor_api_credential.get_secret_value(),timeout=timeout),NotificationClient(str(s.notification_api_url),s.notification_api_credential.get_secret_value(),timeout=timeout))
    stopped=False
    def stop(*_):
        nonlocal stopped; stopped=True
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    try:
        while not stopped:
            try:
                reclaimed = reclaim_stale_pending(r, config.stream, config.group, config.consumer, min_idle_ms=int(s.reclaim_idle_seconds * 1000), count=100)
                for entry in reclaimed.entries:
                    if w.process(entry.fields, message_id=entry.id, consumer=config.consumer, redis=r) == "ack":
                        ack_if_owned(r, config.stream, config.group, entry.id, config.consumer)
                w.run_once(r,config)
            except redis.exceptions.RedisError:
                pass
            if a.once: break
            time.sleep(s.poll_interval_seconds)
    finally:
        r.close()
        w.close()
    return 0
