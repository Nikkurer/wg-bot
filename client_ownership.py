"""Client ownership RBAC and owner display helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from operator_add import format_operator_display
from users import UserManager


def format_owner_label(owner_id: Optional[int], um: UserManager) -> str:
    """Human-readable owner for admin client cards."""
    if owner_id is None:
        return "без владельца (legacy)"
    for u in um.list_users():
        if u["id"] == owner_id:
            return format_operator_display(u)
    return f"ID {owner_id} <deleted>"


def can_view_client(actor_id: int, um: UserManager, client: Dict[str, Any]) -> bool:
    if um.is_admin(actor_id):
        return True
    if not client.get("has_local_conf"):
        return False
    return client.get("owner") == actor_id


def can_manage_client(actor_id: int, um: UserManager, client: Dict[str, Any]) -> bool:
    if um.is_admin(actor_id):
        return True
    if not client.get("has_local_conf") or not client.get("storage_name"):
        return False
    if client.get("owner") is None:
        return False
    return client.get("owner") == actor_id


def filter_clients_for_actor(
    clients: List[Dict[str, Any]], actor_id: int, um: UserManager
) -> List[Dict[str, Any]]:
    return [c for c in clients if can_view_client(actor_id, um, c)]
