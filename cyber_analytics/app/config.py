from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets must come from env, never from source."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://vms:vms@localhost:5432/cyber_analytics"
    cyber_hmac_secret: str = "dev-hmac-change-me"
    cyber_admin_api_key: str = "dev-admin-key"


settings = Settings()
