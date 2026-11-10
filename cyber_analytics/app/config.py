from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets must come from env, never from source."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://vms:vms@localhost:5432/cyber_analytics"
    cyber_hmac_secret: str = "dev-hmac-change-me"
    cyber_admin_api_key: str = "dev-admin-key"

    # Detection rule thresholds (configurable via env / .env)
    rule_brute_force_window_seconds: int = 60
    rule_brute_force_threshold: int = 5
    rule_credential_stuffing_window_seconds: int = 120
    rule_credential_stuffing_threshold_usernames: int = 3
    rule_impossible_access_window_seconds: int = 300
    rule_mass_export_window_seconds: int = 600  # 10 minutes
    rule_mass_export_threshold: int = 10
    rule_privilege_abuse_window_seconds: int = 300
    rule_privilege_abuse_threshold: int = 3
    rule_camera_heartbeat_timeout_seconds: int = 180  # 3 minutes


settings = Settings()
