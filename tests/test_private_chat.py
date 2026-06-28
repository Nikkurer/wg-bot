"""Tests for private_chat.py."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiogram.enums import ChatType

from messages import PRIVATE_CHAT_CALLBACK
from private_chat import PrivateChatMiddleware, is_private_chat, private_chat


def _message(chat_type: ChatType):
    return SimpleNamespace(chat=SimpleNamespace(type=chat_type))


def _callback(chat_type: ChatType | None, *, has_message: bool = True):
    if not has_message:
        return SimpleNamespace(message=None)
    return SimpleNamespace(message=SimpleNamespace(chat=SimpleNamespace(type=chat_type)))


class TestPrivateChatHelpers:
    def test_private_message(self):
        assert is_private_chat(_message(ChatType.PRIVATE)) is True

    def test_group_message(self):
        assert is_private_chat(_message(ChatType.GROUP)) is False

    def test_private_callback(self):
        assert is_private_chat(_callback(ChatType.PRIVATE)) is True

    def test_callback_without_message(self):
        assert private_chat(_callback(None, has_message=False)) is None
        assert is_private_chat(_callback(None, has_message=False)) is False


@pytest.mark.asyncio
class TestPrivateChatMiddleware:
    async def test_passes_private_message_to_handler(self):
        middleware = PrivateChatMiddleware()
        handler = AsyncMock(return_value="ok")
        event = _message(ChatType.PRIVATE)
        result = await middleware(handler, event, {})
        handler.assert_awaited_once_with(event, {})
        assert result == "ok"

    async def test_blocks_group_message(self):
        middleware = PrivateChatMiddleware()
        handler = AsyncMock()
        event = _message(ChatType.SUPERGROUP)
        event.answer = AsyncMock()
        result = await middleware(handler, event, {})
        handler.assert_not_awaited()
        event.answer.assert_awaited_once()
        assert result is None

    async def test_blocks_group_callback(self):
        middleware = PrivateChatMiddleware()
        handler = AsyncMock()
        event = _callback(ChatType.GROUP)
        event.answer = AsyncMock()
        result = await middleware(handler, event, {})
        handler.assert_not_awaited()
        event.answer.assert_awaited_once_with(
            PRIVATE_CHAT_CALLBACK,
            show_alert=True,
        )
        assert result is None
