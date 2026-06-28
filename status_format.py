"""Format /status output for user and admin roles."""

from __future__ import annotations

import datetime
import html
from typing import Any, Dict, List, Optional

from config import BotConfig
from wg_admin_client import DriftReport, InterfaceStatus

DEFAULT_ONLINE_THRESHOLD_SEC = 180


def is_client_online(
    client: Dict[str, Any],
    *,
    online_threshold_sec: int,
    now: Optional[float] = None,
) -> bool:
    hs = client.get("latest_handshake")
    if not hs:
        return False
    if now is None:
        now = datetime.datetime.now().timestamp()
    return (now - hs) <= online_threshold_sec


def count_clients_online(
    clients: List[Dict[str, Any]], *, online_threshold_sec: int
) -> int:
    now = datetime.datetime.now().timestamp()
    return sum(
        1
        for c in clients
        if is_client_online(c, online_threshold_sec=online_threshold_sec, now=now)
    )


def _entry_up(status: InterfaceStatus) -> bool:
    return (status.state or "").upper() == "UP"


def format_vpn_server_line(status: InterfaceStatus, *, is_admin: bool) -> str:
    name = status.name or "unknown"
    if _entry_up(status):
        if is_admin:
            return f"🟢 Entry: {name} — UP"
        return "🟢 VPN-сервер"
    state = status.state or "DOWN"
    if is_admin:
        return f"🔴 Entry: {name} — {state}"
    return f"🔴 VPN-сервер — интерфейс {state}"


def format_endpoint_line(cfg: BotConfig) -> str:
    endpoint = cfg.client_endpoint()
    if endpoint:
        return f"📡 Endpoint: {endpoint}"
    return "📡 Endpoint: не задан"


def format_client_summary_line(
    clients: List[Dict[str, Any]], *, online_threshold_sec: int, is_admin: bool
) -> str:
    total = len(clients)
    online = count_clients_online(clients, online_threshold_sec=online_threshold_sec)
    prefix = "👥 Клиенты" if is_admin else "👤 Клиенты"
    return f"{prefix}: {total} всего / {online} online"


def _drift_issue_count(report: DriftReport) -> int:
    return (
        len(report.only_in_storage)
        + len(report.only_in_wireguard)
        + len(report.mismatch)
    )


def _plural_ru(n: int, one: str, few: str, many: str) -> str:
    n_abs = abs(n) % 100
    n1 = n_abs % 10
    if 11 <= n_abs <= 19:
        return many
    if n1 == 1:
        return one
    if 2 <= n1 <= 4:
        return few
    return many


def format_drift_status_line(report: DriftReport) -> str:
    if report.in_sync:
        return "✅ Storage: in sync"
    count = _drift_issue_count(report)
    word = _plural_ru(count, "расхождение", "расхождения", "расхождений")
    return f"⚠️ Storage: drift detected ({count} {word}) — /drift для деталей"


def format_status_message(
    *,
    status: InterfaceStatus,
    clients: List[Dict[str, Any]],
    cfg: BotConfig,
    is_admin: bool,
    online_threshold_sec: int = DEFAULT_ONLINE_THRESHOLD_SEC,
    drift_report: Optional[DriftReport] = None,
) -> str:
    lines = ["📊 Статус VPN", "", format_vpn_server_line(status, is_admin=is_admin)]
    summary = format_client_summary_line(
        clients, online_threshold_sec=online_threshold_sec, is_admin=is_admin
    )
    endpoint = format_endpoint_line(cfg)
    show_endpoint = (not is_admin and _entry_up(status)) or (
        is_admin and _entry_up(status)
    )
    if is_admin:
        lines.append(summary)
        if show_endpoint:
            lines.append(endpoint)
        if drift_report is not None:
            lines.append(format_drift_status_line(drift_report))
    else:
        if show_endpoint:
            lines.append(endpoint)
        lines.append("")
        lines.append(summary)
    return "\n".join(lines)


def format_status_error(*, is_admin: bool, error: str) -> str:
    if is_admin:
        safe = html.escape(error)
        return f"📊 Статус VPN\n\n🔴 Entry: недоступен — {safe}"
    return "📊 Статус VPN\n\n🔴 VPN-сервер — сервис временно недоступен"
