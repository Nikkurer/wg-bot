"""Tests for client_manager.py."""
import json
from unittest.mock import patch

import pytest

from client_manager import ClientManager, ClientManagerError
from config import BotConfig


@pytest.fixture
def bot_config(tmp_path):
    client_dir = tmp_path / "clients"
    client_dir.mkdir()
    return BotConfig(
        client_dir=str(client_dir),
        wg_subnet="10.66.66.0/24",
        telegram_token="token",
        allowed_users=[1],
        wg_subnet_v6="fd66:66::/64",
        server_public_key="SERVER_PUB_KEY",
        server_endpoint="vpn.example.com",
        wg_dns="10.66.66.1",
    )


@pytest.fixture
def manager(bot_config):
    return ClientManager(bot_config, verify_dir=False)


class TestClientManager:
    def test_validate_name(self, manager):
        manager.validate_name("alice-1")
        with pytest.raises(ClientManagerError, match="Invalid"):
            manager.validate_name("bad name")

    def test_generate_keypair(self, manager):
        with patch("client_manager.subprocess.run") as mock_run:
            mock_run.side_effect = [
                type("R", (), {"stdout": "privkey", "returncode": 0})(),
                type("R", (), {"stdout": "pubkey", "returncode": 0})(),
            ]
            priv, pub = manager.generate_keypair()
            assert priv == "privkey"
            assert pub == "pubkey"
            assert mock_run.call_args_list[0][0][0] == ["wg", "genkey"]

    def test_parse_peer_ips(self, manager):
        v4, v6 = manager.parse_peer_ips(["10.66.66.2/32", "fd66:66::2/128"])
        assert v4 == "10.66.66.2/32"
        assert v6 == "fd66:66::2/128"

    def test_parse_peer_ips_ipv4_only(self, manager):
        v4, v6 = manager.parse_peer_ips(["10.66.66.2/32"])
        assert v4 == "10.66.66.2/32"
        assert v6 is None

    def test_derive_ipv6_from_ipv4(self, manager):
        v6 = manager.derive_ipv6_from_ipv4("10.66.66.10/32")
        assert v6 == "fd66:66::a/128"

    def test_build_client_conf(self, manager):
        conf = manager.build_client_conf(
            "PRIVATE", "10.66.66.10/32", "fd66:66::10/128"
        )
        assert "PrivateKey = PRIVATE" in conf
        assert "Address = 10.66.66.10/32, fd66:66::10/128" in conf
        assert "PublicKey = SERVER_PUB_KEY" in conf
        assert "Endpoint = vpn.example.com:443" in conf
        assert "DNS = 10.66.66.1" in conf

    def test_save_and_load_client(self, manager):
        record = manager.save_client(
            "alice",
            "pubkey123",
            "10.66.66.10/32",
            "[Interface]\nPrivateKey = x\n",
            client_ip_v6="fd66:66::10/128",
        )
        assert record.name == "alice"
        loaded = manager.load_client("alice")
        assert loaded.pubkey == "pubkey123"
        assert loaded.client_ip_v6 == "fd66:66::10/128"
        assert manager.read_conf("alice").startswith("[Interface]")

    def test_remove_client_files(self, manager):
        manager.save_client("bob", "pk", "10.66.66.11/32", "conf")
        manager.remove_client_files("bob")
        assert not manager.name_exists("bob")

    def test_update_client_after_rotate(self, manager):
        manager.save_client("carol", "oldpk", "10.66.66.12/32", "old conf")
        updated = manager.update_client_after_rotate("carol", "newpk", "new conf")
        assert updated.pubkey == "newpk"
        assert manager.load_client("carol").pubkey == "newpk"
        assert manager.read_conf("carol") == "new conf"
