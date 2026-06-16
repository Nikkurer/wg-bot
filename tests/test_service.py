"""Tests for service.py."""
import json
from unittest.mock import AsyncMock, patch

import pytest

from client_manager import ClientManager
from config import BotConfig
from service import ClientService, ClientServiceError
from wg_admin_client import PeerInfo, WgAdminClient, WgAdminError


@pytest.fixture
def bot_config(tmp_path):
    client_dir = tmp_path / "clients"
    client_dir.mkdir()
    return BotConfig(
        wg_interface="wg-ru-clients",
        client_dir=str(client_dir),
        wg_subnet="10.66.66.0/24",
        telegram_token="token",
        allowed_users=[1],
        wg_subnet_v6="fd66:66::/64",
        server_public_key="SERVER_PUB_KEY",
        server_endpoint="vpn.example.com",
    )


@pytest.fixture
def client_manager(bot_config):
    yield ClientManager(bot_config, verify_dir=False)


@pytest.fixture
def wg_admin():
    mock = AsyncMock(spec=WgAdminClient)
    mock.list_peers.return_value = []
    return mock


@pytest.fixture
def service(bot_config, wg_admin, client_manager):
    return ClientService(bot_config, wg_admin, client_manager=client_manager)


class TestClientService:
    @pytest.mark.asyncio
    async def test_create_client(self, service, wg_admin):
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv", "pub")
        ):
            result = await service.create_client("alice")

        wg_admin.add_peer.assert_awaited_once()
        call = wg_admin.add_peer.await_args
        assert call.kwargs["public_key"] == "pub"
        assert call.kwargs["description"] == "alice"
        assert result.record.name == "alice"
        assert "PrivateKey = priv" in result.conf_text
        assert service.clients.name_exists("alice")

    @pytest.mark.asyncio
    async def test_create_rollback_on_save_failure(self, service, wg_admin):
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv", "pub")
        ), patch.object(
            service.clients, "save_client", side_effect=OSError("disk full")
        ):
            with pytest.raises(ClientServiceError, match="Failed to save"):
                await service.create_client("bob")
        wg_admin.remove_peer.assert_awaited_once_with("pub")

    @pytest.mark.asyncio
    async def test_delete_client(self, service, wg_admin):
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv", "pub")
        ):
            await service.create_client("carol")
        await service.delete_client("carol")
        wg_admin.remove_peer.assert_awaited_with("pub")
        assert not service.clients.name_exists("carol")

    @pytest.mark.asyncio
    async def test_rotate_client(self, service, wg_admin):
        with patch.object(
            service.clients, "generate_keypair", side_effect=[("priv1", "pub1"), ("priv2", "pub2")]
        ):
            await service.create_client("dave")
        wg_admin.rotate_peer.reset_mock()
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv2", "pub2")
        ):
            result = await service.rotate_client("dave")
        wg_admin.rotate_peer.assert_awaited_once_with("pub1", "pub2")
        assert result.record.pubkey == "pub2"
        assert "priv2" in result.conf_text

    @pytest.mark.asyncio
    async def test_list_clients_merged(self, service, wg_admin):
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv", "pub")
        ):
            await service.create_client("eve")
        wg_admin.list_peers.return_value = [
            PeerInfo(
                public_key="pub",
                allowed_ips=["10.66.66.10/32"],
                description="eve",
                transfer_rx=100,
            )
        ]
        items = await service.list_clients_merged()
        assert len(items) == 1
        assert items[0]["name"] == "eve"
        assert items[0]["transfer_rx"] == 100

    @pytest.mark.asyncio
    async def test_create_fails_if_wg_admin_fails(self, service, wg_admin):
        wg_admin.add_peer.side_effect = WgAdminError("boom")
        with patch.object(
            service.clients, "generate_keypair", return_value=("priv", "pub")
        ):
            with pytest.raises(ClientServiceError, match="Failed to add peer"):
                await service.create_client("fail")
