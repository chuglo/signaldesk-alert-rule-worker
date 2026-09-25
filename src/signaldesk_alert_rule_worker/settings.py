from pydantic import AnyHttpUrl, RedisDsn, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import secrets
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIGNALDESK_", extra="forbid", strict=True)
    control_api_url: AnyHttpUrl
    monitor_api_url: AnyHttpUrl
    notification_api_url: AnyHttpUrl
    redis_url: RedisDsn
    control_api_credential: SecretStr
    monitor_api_credential: SecretStr
    notification_api_credential: SecretStr
    poll_interval_seconds: float = 5.0
    reclaim_idle_seconds: float = 60.0
    request_connect_timeout_seconds: float = 2.0
    request_read_timeout_seconds: float = 5.0
    request_write_timeout_seconds: float = 5.0
    request_pool_timeout_seconds: float = 2.0
    service_name: str = "signaldesk-alert-rule-worker"
    @field_validator("control_api_credential", "monitor_api_credential", "notification_api_credential")
    @classmethod
    def strong(cls, value):
        raw = value.get_secret_value()
        if len(raw) < 32 or not raw.isascii() or any(c.isspace() for c in raw): raise ValueError("service credentials must be strong")
        return value
    @model_validator(mode="after")
    def distinct(self):
        vals = [x.get_secret_value() for x in (self.control_api_credential, self.monitor_api_credential, self.notification_api_credential)]
        if any(secrets.compare_digest(a,b) for i,a in enumerate(vals) for b in vals[:i]): raise ValueError("service credentials must be distinct")
        if any(x <= 0 or x > 60 for x in (self.poll_interval_seconds, self.reclaim_idle_seconds, self.request_connect_timeout_seconds, self.request_read_timeout_seconds, self.request_write_timeout_seconds, self.request_pool_timeout_seconds)): raise ValueError("bounded intervals required")
        return self
