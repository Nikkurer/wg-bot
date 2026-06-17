"""Дополнение конфигурации данными из wg-admin при старте."""

from __future__ import annotations

import dataclasses
import logging
from typing import Optional

from config import BotConfig, ConfigError
from wg_admin_client import WgAdminClient, WgAdminError


async def enrich_from_wg_admin(
    cfg: BotConfig,
    wg_admin: WgAdminClient,
    logger: Optional[logging.Logger] = None,
) -> BotConfig:
    """Подставляет в конфиг значения из wg-admin GET /interface/status."""
    log = logger or logging.getLogger("bootstrap")

    try:
        status = await wg_admin.interface_status()
    except WgAdminError as e:
        if not cfg.server_public_key:
            raise ConfigError(
                "SERVER_PUBLIC_KEY not set in config and wg-admin is unavailable"
            ) from e
        log.warning("wg-admin unavailable at startup, using config as-is: %s", e)
        return cfg

    updates: dict = {}

    if status.name:
        updates["wg_interface"] = status.name
        log.info("Interface from wg-admin: %s", status.name)
    else:
        log.warning("wg-admin returned empty interface name")

    if not cfg.server_public_key:
        if not status.public_key:
            raise ConfigError(
                "SERVER_PUBLIC_KEY not set in config and wg-admin returned empty public_key"
            )
        updates["server_public_key"] = status.public_key
        log.info("SERVER_PUBLIC_KEY from wg-admin (interface %s)", status.name or "?")

    if status.state != "UP":
        log.warning("WireGuard interface state is %s (expected UP)", status.state)

    if not updates:
        return cfg

    return dataclasses.replace(cfg, **updates)
