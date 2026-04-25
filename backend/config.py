from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_CONFIG_FILE = Path(__file__).parent.parent / "config" / "settings.yaml"


def _load_yaml() -> dict:
    if not _CONFIG_FILE.exists():
        return {}
    with open(_CONFIG_FILE) as f:
        raw = f.read()
    # Expand ${VAR} env-var references inside YAML values
    import re
    def _expand(m: re.Match) -> str:
        return os.environ.get(m.group(1), m.group(0))
    raw = re.sub(r"\$\{([^}]+)\}", _expand, raw)
    return yaml.safe_load(raw) or {}


_yaml = _load_yaml()


def _y(*keys: str, default=None):
    """Drill into nested YAML dict with dot-path keys."""
    node = _yaml
    for k in keys:
        if not isinstance(node, dict):
            return default
        node = node.get(k, default)
    return node


class ServerSettings(BaseSettings):
    host: str = _y("server", "host", default="0.0.0.0")
    port: int = _y("server", "port", default=8000)
    workers: int = _y("server", "workers", default=1)
    log_level: str = _y("server", "log_level", default="info")

    model_config = SettingsConfigDict(env_prefix="SERVER_", extra="ignore")


class DatabaseSettings(BaseSettings):
    path: str = _y("database", "path", default="./data/siem.duckdb")
    max_memory: str = _y("database", "max_memory", default="2GB")
    threads: int = _y("database", "threads", default=4)
    backup_interval_hours: int = _y("database", "backup_interval_hours", default=24)
    retention_days: int = _y("database", "retention_days", default=90)

    model_config = SettingsConfigDict(env_prefix="DB_", extra="ignore")


class AuthSettings(BaseSettings):
    secret_key: str = _y("auth", "secret_key", default="change-me-in-production")
    access_token_expire_minutes: int = _y("auth", "access_token_expire_minutes", default=60)
    refresh_token_expire_days: int = _y("auth", "refresh_token_expire_days", default=7)

    model_config = SettingsConfigDict(env_prefix="AUTH_", extra="ignore")


class XCockpitSettings(BaseSettings):
    base_url: str = _y("xcockpit", "base_url", default="")
    customer_key: str = _y("xcockpit", "customer_key", default="")
    api_key: str = _y("xcockpit", "api_key", default="")
    pull_interval_seconds: int = _y("xcockpit", "pull_interval_seconds", default=120)
    pull_page_size: int = _y("xcockpit", "pull_page_size", default=50)
    verify_ssl: bool = _y("xcockpit", "verify_ssl", default=True)
    # Sliding window for re-fetching incidents — needed because incident state
    # (InProgress→Investigated→…) changes WITHOUT bumping `created`, so a
    # cursor-based pull would never sync state changes. Default 30 days.
    incidents_refresh_window_days: int = _y("xcockpit", "incidents_refresh_window_days", default=30)

    model_config = SettingsConfigDict(env_prefix="XCOCKPIT_", extra="ignore")


class AlertSettings(BaseSettings):
    evaluation_interval_seconds: int = _y("alerts", "evaluation_interval_seconds", default=60)
    default_eval_window: str = _y("alerts", "default_eval_window", default="-15m")

    model_config = SettingsConfigDict(env_prefix="ALERT_", extra="ignore")


class UISettings(BaseSettings):
    static_dir: str = _y("ui", "static_dir", default="./frontend/dist")
    serve_ui: bool = _y("ui", "serve_ui", default=True)

    model_config = SettingsConfigDict(env_prefix="UI_", extra="ignore")


class Settings:
    server = ServerSettings()
    database = DatabaseSettings()
    auth = AuthSettings()
    xcockpit = XCockpitSettings()
    alerts = AlertSettings()
    ui = UISettings()


settings = Settings()
