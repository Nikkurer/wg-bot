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
        wg_interface="wg-ru-clients",
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
    with patch("client_manager.os.getuid", return_value=1000), patch(
        "client_manager.os.makedirs"
    ), patch("client_manager.os.stat") as mock_stat:
        mock_stat.return_value.st_uid = 1000
        mock_stat.return_value.st_mode = 0o700
        return ClientManager(bot_config)


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

    def test_allocate_ips_empty(self, manager):
        v4, v6 = manager.allocate_ips()
        assert v4.startswith("10.66.66.")
        assert v6 and v6.startswith("fd66:66::")

    def test_allocate_skips_used(self, manager, bot_config):
        meta = {
            "name": "used",
            "client_ip": "10.66.66.2/24",
            "pubkey": "pk",
            "conf_path": str(bot_config.client_dir) + "/used.conf",
        }
        with open(bot_config.client_dir + "/used.json", "w") as f:
            json.dump(meta, f)
        v4, _ = manager.allocate_ips()
        assert v4.startswith("10.66.66.") and not v4.startswith("10.66.66.2/")

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
