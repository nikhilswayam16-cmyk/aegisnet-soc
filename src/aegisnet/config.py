"""Small environment-driven settings module; no secrets are bundled with the project."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str = os.getenv("AEGIS_DATABASE_URL", "sqlite:///./aegisnet.db")
    api_key: str = os.getenv("AEGIS_API_KEY", "")
    log_level: str = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    max_batch_size: int = 500


settings = Settings()
