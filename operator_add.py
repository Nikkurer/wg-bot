"""Helpers for resolving Telegram user id when adding operators."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

ADD_USER_REQUEST_ID = 1


def profile_from_fields(
    *,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    username: Optional[str] = None,
) -> Dict[str, str]:
    """Build optional profile dict for users.json (only non-empty fields)."""
    profile: Dict[str, str] = {}
    if first_name:
        profile["first_name"] = first_name
    if last_name:
        profile["last_name"] = last_name
    if username:
        profile["username"] = username.lstrip("@")
    return profile


def format_person_name(
    *,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    username: Optional[str] = None,
    user_id: int,
) -> str:
    return format_operator_display(
        {
            "id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
        }
    )


def format_operator_display(user: Dict[str, Any]) -> str:
    """Human-readable operator label: name, then @username, then id."""
    name = " ".join(
        p for p in (user.get("first_name") or "", user.get("last_name") or "") if p
    ).strip()
    username = user.get("username")
    uname = f"@{str(username).lstrip('@')}" if username else None

    if name and uname:
        return f"{name} ({uname})"
    if name:
        return name
    if uname:
        return uname
    return str(user["id"])


def pending_profile_from_fsm(data: dict, user_id: int) -> Dict[str, str]:
    """Profile from FSM after contact/picker selection (before role is chosen)."""
    pending_id = data.get("pending_user_id")
    if pending_id is None:
        return {}
    try:
        if int(pending_id) != int(user_id):
            return {}
    except (TypeError, ValueError):
        return {}
    return profile_from_fields(
        first_name=data.get("pending_first_name"),
        last_name=data.get("pending_last_name"),
        username=data.get("pending_username"),
    )


def contact_user_id_or_error(user_id: Optional[int]) -> Tuple[Optional[int], Optional[str]]:
    if not user_id:
        return None, (
            "У этого контакта нет Telegram ID — возможно, человек "
            "не зарегистрирован в Telegram."
        )
    return user_id, None
