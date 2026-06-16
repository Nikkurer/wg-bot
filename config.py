"""Загрузка и валидация конфигурации wg-bot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

import yaml

# v1 — обязательны для текущего бота; v2-ключи опциональны до переключения handlers
REQUIRED_KEYS = ("WG_INTERFACE", "CLIENT_DIR", "WG_SUBNET", "TELEGRAM_TOKEN", "ALLOWED_USERS")

ENV_OVERRIDES = {
    "TELEGRAM_TOKEN": "TELEGRAM_TOKEN",
    "USERS_FILE": "USERS_FILE",
    "WG_ADMIN_SOCKET": "WG_ADMIN_SOCKET",
}


class ConfigError(Exception):
    """Ошибка загрузки или валидации конфигурации."""


@dataclass(frozen=True)
class BotConfig:
    """Конфигурация бота."""

    wg_interface: str
    client_dir: str
    wg_subnet: str
    telegram_token: str
    allowed_users: List[int]

    users_file: str = "users.json"
    wg_config_dir: Optional[str] = None
    server_public_key: Optional[str] = None
    server_ip: Optional[str] = None

    # v2 / wg-install RU
    wg_admin_socket: str = "/run/wg-admin/wg-admin.sock"
    wg_subnet_v6: Optional[str] = None
    server_endpoint: Optional[str] = None
    wg_client_port: int = 443
    wg_mtu: int = 1420
    wg_dns: str = "10.66.66.1"
    client_allowed_ips: str = "0.0.0.0/0, ::/0"
    persistent_keepalive: int = 25

    def as_dict(self) -> dict:
        """Словарь для обратной совместимости с handlers v1."""
        return {
            "WG_INTERFACE": self.wg_interface,
            "CLIENT_DIR": self.client_dir,
            "WG_SUBNET": self.wg_subnet,
            "TELEGRAM_TOKEN": self.telegram_token,
            "ALLOWED_USERS": self.allowed_users,
            "USERS_FILE": self.users_file,
            "WG_CONFIG_DIR": self.wg_config_dir,
            "SERVER_PUBLIC_KEY": self.server_public_key,
            "SERVER_IP": self.server_ip,
            "WG_ADMIN_SOCKET": self.wg_admin_socket,
            "WG_SUBNET_V6": self.wg_subnet_v6,
            "SERVER_ENDPOINT": self.server_endpoint,
            "WG_CLIENT_PORT": self.wg_client_port,
            "WG_MTU": self.wg_mtu,
            "WG_DNS": self.wg_dns,
            "CLIENT_ALLOWED_IPS": self.client_allowed_ips,
            "PERSISTENT_KEEPALIVE": self.persistent_keepalive,
        }

    def endpoint_host(self) -> str:
        """Hostname или IP для client Endpoint (SERVER_ENDPOINT или SERVER_IP)."""
        return self.server_endpoint or self.server_ip or ""

    def client_endpoint(self) -> str:
        """Полный Endpoint для client .conf: host:port."""
        host = self.endpoint_host()
        if not host:
            return ""
        return f"{host}:{self.wg_client_port}"


def load_config(path: str, *, check_client_dir: bool = True) -> BotConfig:
    """Загружает конфигурацию из YAML с env overrides.

    Args:
        path: Путь к config.yaml.
        check_client_dir: Если True, CLIENT_DIR должен существовать.

    Raises:
        ConfigError: Невалидный или неполный конфиг.
    """
    if not path or not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a mapping")

    for key in REQUIRED_KEYS:
        if key not in raw:
            raise ConfigError(f"Missing required config key: {key}")

    allowed = raw["ALLOWED_USERS"]
    if not isinstance(allowed, list) or not allowed:
        raise ConfigError("ALLOWED_USERS must be a non-empty list")

    try:
        allowed_users = [int(uid) for uid in allowed]
    except (TypeError, ValueError) as e:
        raise ConfigError(f"ALLOWED_USERS must contain integers: {e}") from e

    client_dir = str(raw["CLIENT_DIR"])
    if check_client_dir and not os.path.isdir(client_dir):
        raise ConfigError(f"CLIENT_DIR not found: {client_dir}")

    cfg = BotConfig(
        wg_interface=str(raw["WG_INTERFACE"]),
        client_dir=client_dir,
        wg_subnet=str(raw["WG_SUBNET"]),
        telegram_token=str(raw["TELEGRAM_TOKEN"]),
        allowed_users=allowed_users,
        users_file=str(raw.get("USERS_FILE", "users.json")),
        wg_config_dir=_optional_str(raw.get("WG_CONFIG_DIR")),
        server_public_key=_optional_str(raw.get("SERVER_PUBLIC_KEY")),
        server_ip=_optional_str(raw.get("SERVER_IP")),
        wg_admin_socket=str(raw.get("WG_ADMIN_SOCKET", "/run/wg-admin/wg-admin.sock")),
        wg_subnet_v6=_optional_str(raw.get("WG_SUBNET_V6")),
        server_endpoint=_optional_str(raw.get("SERVER_ENDPOINT")),
        wg_client_port=int(raw.get("WG_CLIENT_PORT", 443)),
        wg_mtu=int(raw.get("WG_MTU", 1420)),
        wg_dns=str(raw.get("WG_DNS", "10.66.66.1")),
        client_allowed_ips=str(raw.get("CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0")),
        persistent_keepalive=int(raw.get("PERSISTENT_KEEPALIVE", 25)),
    )

    for cfg_field, env_name in ENV_OVERRIDES.items():
        env_val = os.environ.get(env_name)
        if not env_val:
            continue
        if cfg_field == "TELEGRAM_TOKEN":
            object.__setattr__(cfg, "telegram_token", env_val)
        elif cfg_field == "USERS_FILE":
            object.__setattr__(cfg, "users_file", env_val)
        elif cfg_field == "WG_ADMIN_SOCKET":
            object.__setattr__(cfg, "wg_admin_socket", env_val)

    if not cfg.telegram_token or cfg.telegram_token.startswith("REPLACE"):
        if os.environ.get("TELEGRAM_TOKEN"):
            pass  # already overridden
        elif cfg.telegram_token.startswith("REPLACE"):
            raise ConfigError("Set TELEGRAM_TOKEN in config or environment")

    return cfg


def _optional_str(value) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None
