"""
Centralized application configuration.

Nothing else in the codebase should call os.environ directly for these
values. Import `settings` from here instead, so there is exactly one
place that knows how configuration is sourced.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


# =========================================================
# PROJECT PATHS
# =========================================================

# settings.py
#     ↓
# app/
#     ↓
# backend/
#
# Therefore:
#
# Path(__file__).resolve().parents[2]
#
# points to the backend directory.

BASE_DIR = Path(
    __file__
).resolve().parents[2]

ENV_FILE = BASE_DIR / ".env"


# =========================================================
# APPLICATION SETTINGS
# =========================================================

class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # =====================================================
    # LLM
    # =====================================================

    groq_api_key: str | None = None

    groq_model: str = (
        "openai/gpt-oss-120b"
    )

    # =====================================================
    # DATABASE
    # =====================================================

    database_url: str = (
        "postgresql+psycopg2://soc:soc@db:5432/soc_agent"
    )

    jwt_secret_key: str = "change-me-in-production"
    jwt_expire_minutes: int = 480

    # =====================================================
    # LOG SOURCE
    # =====================================================

    log_source: str = "local"

    sentinel_tenant_id: str | None = None

    sentinel_client_id: str | None = None

    sentinel_client_secret: str | None = None

    sentinel_workspace_id: str | None = None

    # =====================================================
    # IOC ENRICHMENT
    # =====================================================

    vt_api_key: str | None = None

    abuseipdb_api_key: str | None = None

    # =====================================================
    # EMAIL / PASSWORD RESET
    # =====================================================

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587

    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None

    @property
    def smtp_configured(self) -> bool:
        return bool(
            self.smtp_username
            and self.smtp_password
            and self.smtp_from_email
        )

    # =====================================================
    # APPLICATION
    # =====================================================

    app_env: str = "development"

    log_level: str = "INFO"

    # =====================================================
    # HELPERS
    # =====================================================

    @property
    def groq_configured(self) -> bool:
        return bool(
            self.groq_api_key
        )


# =========================================================
# SINGLE SETTINGS INSTANCE
# =========================================================

settings = Settings()