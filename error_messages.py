"""Map exceptions to safe Telegram-facing text."""

from __future__ import annotations

import html

from client_manager import ClientManagerError
from messages import (
    ACCESS_DENIED,
    CLIENT_ALREADY_EXISTS,
    CLIENT_NOT_FOUND,
    INVALID_CLIENT_NAME,
    ROTATE_MANUAL_REISSUE,
)
from service import ClientServiceError
from users import UserManagerError

GENERIC_ERROR = (
    "Произошла ошибка. Попробуйте позже или обратитесь к администратору."
)
GENERIC_CLIENT_ERROR = "Ошибка при работе с клиентом."
GENERIC_CALLBACK_ALERT = "Ошибка операции."

_SAFE_CLIENT_MANAGER_MESSAGES = frozenset(
    {
        INVALID_CLIENT_NAME,
        CLIENT_ALREADY_EXISTS,
        CLIENT_NOT_FOUND,
    }
)

_SAFE_CLIENT_SERVICE_MESSAGES = frozenset(
    {
        INVALID_CLIENT_NAME,
        CLIENT_ALREADY_EXISTS,
        ACCESS_DENIED,
        ROTATE_MANUAL_REISSUE,
    }
)


def user_facing_error(exc: Exception) -> str:
    """Return text safe to show in Telegram (no paths, stack traces, wg-admin)."""
    if isinstance(exc, UserManagerError):
        return str(exc)
    if isinstance(exc, ClientManagerError):
        msg = str(exc)
        if msg in _SAFE_CLIENT_MANAGER_MESSAGES:
            return msg
        return GENERIC_CLIENT_ERROR
    if isinstance(exc, ClientServiceError):
        msg = str(exc)
        if msg in _SAFE_CLIENT_SERVICE_MESSAGES:
            return msg
        return GENERIC_CLIENT_ERROR
    return GENERIC_ERROR


def admin_diagnostic_detail(exc: Exception) -> str:
    """Escaped exception text for admin-only diagnostic messages."""
    return html.escape(str(exc))


def format_drift_error(exc: Exception) -> str:
    return f"❌ Ошибка drift check: {admin_diagnostic_detail(exc)}"
