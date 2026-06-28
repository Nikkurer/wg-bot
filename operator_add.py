"""Helpers for resolving Telegram user id when adding operators."""

from __future__ import annotations

from typing import Optional, Tuple

ADD_USER_REQUEST_ID = 1


def format_person_name(
    *,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    username: Optional[str] = None,
    user_id: int,
) -> str:
    parts = [first_name or "", last_name or ""]
    name = " ".join(p for p in parts if p).strip()
    if name:
        return name
    if username:
        return f"@{username.lstrip('@')}"
    return str(user_id)


def contact_user_id_or_error(user_id: Optional[int]) -> Tuple[Optional[int], Optional[str]]:
    if not user_id:
        return None, (
            "У этого контакта нет Telegram ID — возможно, человек "
            "не зарегистрирован в Telegram."
        )
    return user_id, None
