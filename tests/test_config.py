"""Tests for config.py."""
import os

import pytest

from config import BotConfig, ConfigError, load_config


@pytest.fixture
def config_file(tmp_path):
    client_dir = tmp_path / "clients"
    client_dir.mkdir()

    def _write(**overrides):
        lines = [
            f'CLIENT_DIR: "{client_dir}"',
            'WG_SUBNET: "10.66.66.0/24"',
            'TELEGRAM_TOKEN: "test-token-123456789012345678901234"',
            "ALLOWED_USERS:",
            "  - 111",
        ]
        for key, value in overrides.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {item}")
            elif isinstance(value, str):
                lines.append(f'{key}: "{value}"')
            else:
                lines.append(f"{key}: {value}")
        path = tmp_path / "config.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    return _write


class TestLoadConfig:
    def test_load_minimal(self, config_file):
        path = config_file()
        cfg = load_config(str(path))
        assert cfg.wg_interface is None
        assert cfg.wg_subnet == "10.66.66.0/24"
        assert cfg.allowed_users == [111]
        assert cfg.wg_admin_socket == "/run/wg-admin/wg-admin.sock"
        assert cfg.wg_client_port == 443

    def test_load_v2_fields(self, config_file):
        path = config_file(
            WG_SUBNET_V6="fd66:66::/64",
            SERVER_ENDPOINT="vpn.example.com",
            SERVER_PUBLIC_KEY="abc123",
            WG_DNS="10.66.66.1",
            USERS_FILE="/app/state/users.json",
        )
        cfg = load_config(str(path))
        assert cfg.wg_subnet_v6 == "fd66:66::/64"
        assert cfg.server_endpoint == "vpn.example.com"
        assert cfg.client_endpoint() == "vpn.example.com:443"
        assert cfg.users_file == "/app/state/users.json"

    def test_env_override_token(self, config_file, monkeypatch):
        path = config_file()
        monkeypatch.setenv("TELEGRAM_TOKEN", "env-token")
        cfg = load_config(str(path))
        assert cfg.telegram_token == "env-token"

    def test_token_from_env_without_yaml_key(self, config_file, monkeypatch):
        path = config_file()
        text = path.read_text(encoding="utf-8")
        text = "\n".join(
            line for line in text.splitlines() if not line.startswith("TELEGRAM_TOKEN:")
        )
        path.write_text(text + "\n", encoding="utf-8")
        monkeypatch.setenv("TELEGRAM_TOKEN", "env-only-token")
        cfg = load_config(str(path))
        assert cfg.telegram_token == "env-only-token"

    def test_token_required(self, config_file, monkeypatch):
        path = config_file()
        text = path.read_text(encoding="utf-8")
        text = "\n".join(
            line for line in text.splitlines() if not line.startswith("TELEGRAM_TOKEN:")
        )
        path.write_text(text + "\n", encoding="utf-8")
        monkeypatch.delenv("TELEGRAM_TOKEN", raising=False)
        with pytest.raises(ConfigError, match="TELEGRAM_TOKEN"):
            load_config(str(path))

    def test_default_container_paths(self, config_file, monkeypatch):
        path = config_file()
        text = path.read_text(encoding="utf-8")
        for key in ("CLIENT_DIR:", "USERS_FILE:", "WG_ADMIN_SOCKET:"):
            text = "\n".join(line for line in text.splitlines() if not line.startswith(key))
        path.write_text(text + "\n", encoding="utf-8")
        monkeypatch.setenv("TELEGRAM_TOKEN", "env-token")
        cfg = load_config(str(path), check_client_dir=False)
        assert cfg.client_dir == "/var/lib/wg/clients"
        assert cfg.users_file == "/app/state/users.json"
        assert cfg.wg_admin_socket == "/run/wg-admin/wg-admin.sock"

    def test_env_override_socket(self, config_file, monkeypatch):
        path = config_file()
        monkeypatch.setenv("WG_ADMIN_SOCKET", "/tmp/wg.sock")
        cfg = load_config(str(path))
        assert cfg.wg_admin_socket == "/tmp/wg.sock"

    def test_missing_required_key(self, config_file):
        path = config_file()
        text = path.read_text(encoding="utf-8").replace("WG_SUBNET:", "REMOVED:")
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigError, match="WG_SUBNET"):
            load_config(str(path))

    def test_missing_client_dir(self, config_file):
        path = config_file(CLIENT_DIR="/nonexistent/path")
        with pytest.raises(ConfigError, match="CLIENT_DIR"):
            load_config(str(path))

    def test_skip_client_dir_check(self, config_file):
        path = config_file(CLIENT_DIR="/nonexistent/path")
        with pytest.raises(ConfigError):
            load_config(str(path))
        cfg = load_config(str(path), check_client_dir=False)
        assert cfg.client_dir == "/nonexistent/path"

    def test_as_dict_backward_compat(self, config_file):
        cfg = load_config(str(config_file()))
        d = cfg.as_dict()
        assert d["WG_INTERFACE"] is None
        assert d["WG_ADMIN_SOCKET"] == "/run/wg-admin/wg-admin.sock"

    def test_endpoint_host_fallback(self, config_file):
        cfg = load_config(str(config_file(SERVER_IP="1.2.3.4")))
        assert cfg.endpoint_host() == "1.2.3.4"
        assert cfg.client_endpoint() == "1.2.3.4:443"
