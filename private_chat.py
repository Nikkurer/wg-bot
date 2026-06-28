"""Restrict bot handlers to private Telegram chats."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Optional

from aiogram import BaseMiddleware
from aiogram.enums import ChatType
from aiogram.types import TelegramObject

from messages import PRIVATE_CHAT_CALLBACK, PRIVATE_CHAT_ONLY


def private_chat(event: TelegramObject) -> Optional[ChatType]:
    """Return chat type for message/callback events, or None if unknown."""
    chat = getattr(event, "chat", None)
    if chat is not None:
        return chat.type
    message = getattr(event, "message", None)
    if message is not None:
        chat = getattr(message, "chat", None)
        if chat is not None:
            return chat.type
    return None


def is_private_chat(event: TelegramObject) -> bool:
    return private_chat(event) == ChatType.PRIVATE


class PrivateChatMiddleware(BaseMiddleware):
    """Block group/supergroup/channel usage — VPN data must not leak to audiences."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        if is_private_chat(event):
            return await handler(event, data)

        answer = getattr(event, "answer", None)
        if callable(answer):
            if getattr(event, "message", None) is not None:
                await answer(PRIVATE_CHAT_CALLBACK, show_alert=True)
            else:
                await answer(PRIVATE_CHAT_ONLY)
        return None
