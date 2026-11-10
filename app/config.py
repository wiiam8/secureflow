from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULT_KEY = "dev-insecure-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"  # "production" refuses insecure defaults
    database_url: str = "sqlite:///./secureflow.db"
    secret_key: str = INSECURE_DEFAULT_KEY
    base_url: str = "http://localhost:8000"
    cookie_secure: bool = False  # set true behind HTTPS

    max_report_bytes: int = 10_000_000
    access_token_ttl_minutes: int = 480

    # First admin, created at startup when the users table is empty.
    admin_username: str = "admin"
    admin_email: str = "admin@secureflow.local"
    admin_password: str = ""  # empty -> random password printed once in the logs

    login_max_attempts: int = 5
    login_window_seconds: int = 300

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        return url

    def validate_for_runtime(self) -> None:
        if self.environment == "production" and self.secret_key == INSECURE_DEFAULT_KEY:
            raise RuntimeError("SECRET_KEY must be set to a strong random value in production.")
        if len(self.secret_key) < 16:
            raise RuntimeError("SECRET_KEY is too short (minimum 16 characters).")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
