"""Tests for status_format.py."""

import datetime
import time

import pytest

from config import BotConfig
from status_format import (
    count_clients_online,
    format_client_summary_line,
    format_drift_status_line,
    format_status_error,
    format_status_message,
    format_vpn_server_line,
    is_client_online,
)
from wg_admin_client import DriftReport, DriftPeer, InterfaceStatus


@pytest.fixture
def bot_config():
    return BotConfig(
        client_dir="/tmp/clients",
        wg_subnet="10.66.66.0/24",
        telegram_token="token",
        allowed_users=[1],
        server_endpoint="vpn.example.com",
        status_online_threshold_sec=180,
    )


@pytest.fixture
def interface_up():
    return InterfaceStatus(name="wg-ru-clients", public_key="pk", state="UP", peers=[])


def test_is_client_online_within_threshold():
    now = datetime.datetime(2026, 6, 27, 12, 0, 0).timestamp()
    client = {"latest_handshake": now - 60}
    assert is_client_online(client, online_threshold_sec=180, now=now) is True


def test_is_client_online_outside_threshold():
    now = datetime.datetime(2026, 6, 27, 12, 0, 0).timestamp()
    client = {"latest_handshake": now - 300}
    assert is_client_online(client, online_threshold_sec=180, now=now) is False


def test_is_client_online_never_connected():
    assert is_client_online({}, online_threshold_sec=180) is False


def test_count_clients_online():
    now = time.time()
    clients = [
        {"latest_handshake": now - 30},
        {"latest_handshake": now - 400},
        {},
    ]
    assert count_clients_online(clients, online_threshold_sec=180) == 1


def test_format_vpn_server_line_user_and_admin():
    status = InterfaceStatus(name="wg-ru-clients", public_key="pk", state="UP")
    assert format_vpn_server_line(status, is_admin=False) == "🟢 VPN-сервер"
    assert format_vpn_server_line(status, is_admin=True) == "🟢 Entry: wg-ru-clients — UP"


def test_format_vpn_server_line_down():
    status = InterfaceStatus(name="wg-ru-clients", public_key="pk", state="DOWN")
    assert "🔴 VPN-сервер" in format_vpn_server_line(status, is_admin=False)
    assert "🔴 Entry: wg-ru-clients — DOWN" == format_vpn_server_line(status, is_admin=True)


def test_format_client_summary_line():
    now = time.time()
    clients = [{"latest_handshake": now - 10}, {"latest_handshake": now - 500}]
    assert format_client_summary_line(clients, online_threshold_sec=180, is_admin=True) == (
        "👥 Клиенты: 2 всего / 1 online"
    )
    assert format_client_summary_line(clients, online_threshold_sec=180, is_admin=False) == (
        "👤 Клиенты: 2 всего / 1 online"
    )


def test_format_drift_status_line():
    in_sync = DriftReport(in_sync=True)
    assert format_drift_status_line(in_sync) == "✅ Storage: in sync"

    drift = DriftReport(
        in_sync=False,
        only_in_storage=[DriftPeer(public_key="a", allowed_ips=["10.0.0.1/32"])],
        only_in_wireguard=[DriftPeer(public_key="b", allowed_ips=["10.0.0.2/32"])],
    )
    line = format_drift_status_line(drift)
    assert line.startswith("⚠️ Storage: drift detected (2 расхождения)")


def test_format_status_message_user(interface_up, bot_config):
    now = time.time()
    clients = [{"latest_handshake": now - 20, "owner": 100}]
    text = format_status_message(
        status=interface_up,
        clients=clients,
        cfg=bot_config,
        is_admin=False,
        online_threshold_sec=180,
    )
    assert "🟢 VPN-сервер" in text
    assert "📡 Endpoint: vpn.example.com:443" in text
    assert "👤 Клиенты: 1 всего / 1 online" in text
    assert "Peers:" not in text
    assert "Storage:" not in text


def test_format_status_message_admin(interface_up, bot_config):
    now = time.time()
    clients = [{"latest_handshake": now - 20}]
    drift = DriftReport(in_sync=True)
    text = format_status_message(
        status=interface_up,
        clients=clients,
        cfg=bot_config,
        is_admin=True,
        online_threshold_sec=180,
        drift_report=drift,
    )
    assert "🟢 Entry: wg-ru-clients — UP" in text
    assert "👥 Клиенты: 1 всего / 1 online" in text
    assert "📡 Endpoint: vpn.example.com:443" in text
    assert "✅ Storage: in sync" in text


def test_format_status_error():
    assert "сервис временно недоступен" in format_status_error(
        is_admin=False, error="boom"
    )
    admin = format_status_error(is_admin=True, error="connection refused")
    assert "connection refused" in admin
    assert "недоступен" in admin
