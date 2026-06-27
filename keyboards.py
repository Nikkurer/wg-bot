"""Telegram keyboards and callback_data conventions.

Callback prefixes (max 64 bytes total in callback_data):
  stats:{name}            — client traffic stats
  rotate:ask:{name}       — prompt key rotation confirm
  rotate:confirm:{name}   — execute key rotation
  rotate:cancel           — cancel rotation dialog
  remove:ask:{name}       — prompt client removal confirm
  remove:confirm:{name}   — execute client removal
  remove:cancel           — cancel removal dialog
"""

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)

# --- Reply menu labels ---
BTN_STATUS = "📊 Статус"
BTN_CLIENTS = "👥 Клиенты"
BTN_HELP = "❓ Справка"
BTN_DRIFT = "⚠️ Drift"
BTN_OPERATORS = "👤 Операторы"

VIEWER_MENU_BUTTONS = frozenset({BTN_STATUS, BTN_CLIENTS, BTN_HELP})
ADMIN_MENU_BUTTONS = VIEWER_MENU_BUTTONS | frozenset({BTN_DRIFT, BTN_OPERATORS})

# --- Callback prefixes ---
CB_STATS = "stats"
CB_ROTATE_ASK = "rotate:ask"
CB_ROTATE_CONFIRM = "rotate:confirm"
CB_ROTATE_CANCEL = "rotate:cancel"
CB_REMOVE_ASK = "remove:ask"
CB_REMOVE_CONFIRM = "remove:confirm"
CB_REMOVE_CANCEL = "remove:cancel"


def main_menu(is_admin: bool) -> ReplyKeyboardMarkup:
    """Persistent reply keyboard for registered operators."""
    rows = [
        [KeyboardButton(text=BTN_STATUS), KeyboardButton(text=BTN_CLIENTS)],
        [KeyboardButton(text=BTN_HELP)],
    ]
    if is_admin:
        rows.append(
            [KeyboardButton(text=BTN_DRIFT), KeyboardButton(text=BTN_OPERATORS)]
        )
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)


def client_actions_keyboard(name: str, *, is_admin: bool) -> InlineKeyboardMarkup:
    """Inline actions for a single client row in /listclients."""
    row = [
        InlineKeyboardButton(text="📊 Статистика", callback_data=f"{CB_STATS}:{name}")
    ]
    if is_admin:
        row.extend(
            [
                InlineKeyboardButton(
                    text="🔄 Ротация", callback_data=f"{CB_ROTATE_ASK}:{name}"
                ),
                InlineKeyboardButton(
                    text="🗑 Удалить", callback_data=f"{CB_REMOVE_ASK}:{name}"
                ),
            ]
        )
    return InlineKeyboardMarkup(inline_keyboard=[row])


def rotate_confirm_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Подтвердить",
                    callback_data=f"{CB_ROTATE_CONFIRM}:{name}",
                ),
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_ROTATE_CANCEL
                ),
            ]
        ]
    )


def remove_confirm_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Удалить", callback_data=f"{CB_REMOVE_CONFIRM}:{name}"
                ),
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_REMOVE_CANCEL
                ),
            ]
        ]
    )
