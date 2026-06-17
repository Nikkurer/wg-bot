"""Tests for bootstrap.py."""
import pytest

from bootstrap import enrich_from_wg_admin
from config import BotConfig, ConfigError
from wg_admin_client import InterfaceStatus, WgAdminClient, WgAdminError


def _cfg(**overrides) -> BotConfig:
    base = dict(
        client_dir="/tmp/clients",
        wg_subnet="10.66.66.0/24",
        telegram_token="token",
        allowed_users=[1],
    )
    base.update(overrides)
    return BotConfig(**base)


class MockWgAdmin:
    def __init__(self, status: InterfaceStatus | None = None, error: Exception | None = None):
        self._status = status
        self._error = error

    async def interface_status(self) -> InterfaceStatus:
        if self._error:
            raise self._error
        return self._status


@pytest.mark.asyncio
async def test_enrich_server_public_key():
    cfg = _cfg(server_public_key=None)
    admin = MockWgAdmin(
        InterfaceStatus(name="wg-ru-clients", public_key="server_pubkey_base64", state="UP")
    )
    enriched = await enrich_from_wg_admin(cfg, admin)  # type: ignore[arg-type]
    assert enriched.server_public_key == "server_pubkey_base64"
    assert enriched.wg_interface == "wg-ru-clients"


@pytest.mark.asyncio
async def test_enrich_keeps_explicit_server_public_key():
    cfg = _cfg(server_public_key="manual_key")
    admin = MockWgAdmin(
        InterfaceStatus(name="wg-ru-clients", public_key="from_wg_admin", state="UP")
    )
    enriched = await enrich_from_wg_admin(cfg, admin)  # type: ignore[arg-type]
    assert enriched.server_public_key == "manual_key"


@pytest.mark.asyncio
async def test_enrich_fails_without_key_and_wg_admin():
    cfg = _cfg(server_public_key=None)
    admin = MockWgAdmin(error=WgAdminError("socket missing"))
    with pytest.raises(ConfigError, match="SERVER_PUBLIC_KEY"):
        await enrich_from_wg_admin(cfg, admin)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_enrich_fails_on_empty_public_key():
    cfg = _cfg(server_public_key=None)
    admin = MockWgAdmin(InterfaceStatus(name="wg0", public_key="", state="UP"))
    with pytest.raises(ConfigError, match="empty public_key"):
        await enrich_from_wg_admin(cfg, admin)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_enrich_wg_admin_unavailable_with_manual_key():
    cfg = _cfg(server_public_key="manual_key")
    admin = MockWgAdmin(error=WgAdminError("down"))
    enriched = await enrich_from_wg_admin(cfg, admin)  # type: ignore[arg-type]
    assert enriched.server_public_key == "manual_key"
