"""Telegram keyboards and callback_data conventions.

Client actions use WireGuard pubkey in callback_data (stable, fits 64-byte limit).
Use ``build_callback_data()`` for every dynamic callback so length is checked
at keyboard build time.

Callback prefixes:
  stats:{pubkey}          — client traffic stats
  rotate:ask:{pubkey}     — prompt key rotation confirm
  rotate:confirm:{pubkey} — execute key rotation
  rotate:cancel           — cancel rotation dialog
  remove:ask:{pubkey}     — prompt client removal confirm
  remove:confirm:{pubkey} — execute client removal
  remove:cancel           — cancel removal dialog
  clients:page:{n}        — paginated client list (page number, not client id)
  addclient:cancel        — cancel add-client dialog (FSM)
  useradd:* / userremove:* — operator management (Telegram user_id)
"""

from typing import Optional

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    KeyboardButtonRequestUsers,
    ReplyKeyboardMarkup,
)

from operator_add import ADD_USER_REQUEST_ID

# --- Reply menu labels ---
BTN_PICK_USER = "👤 Выбрать пользователя"
BTN_STATUS = "📊 Статус"
BTN_CLIENTS = "👥 Клиенты"
BTN_HELP = "❓ Справка"
BTN_ADD_CLIENT = "➕ Клиент"
BTN_DRIFT = "⚠️ Drift"
BTN_OPERATORS = "👤 Операторы"

VIEWER_MENU_BUTTONS = frozenset({BTN_STATUS, BTN_CLIENTS, BTN_HELP})
ADMIN_MENU_BUTTONS = VIEWER_MENU_BUTTONS | frozenset(
    {BTN_ADD_CLIENT, BTN_DRIFT, BTN_OPERATORS}
)

# --- Callback prefixes ---
CB_STATS = "stats"
CB_ROTATE_ASK = "rotate:ask"
CB_ROTATE_CONFIRM = "rotate:confirm"
CB_ROTATE_CANCEL = "rotate:cancel"
CB_REMOVE_ASK = "remove:ask"
CB_REMOVE_CONFIRM = "remove:confirm"
CB_REMOVE_CANCEL = "remove:cancel"
CB_CLIENTS_PAGE = "clients:page"
CB_ADDCLIENT_CANCEL = "addclient:cancel"
CB_USER_ADD_START = "useradd:start"
CB_USER_ADD_CANCEL = "useradd:cancel"
CB_USER_ADD_ROLE = "useradd:role"
CB_USER_REMOVE_ASK = "userremove:ask"
CB_USER_REMOVE_CONFIRM = "userremove:confirm"
CB_USER_REMOVE_CANCEL = "userremove:cancel"

TELEGRAM_CALLBACK_DATA_MAX_BYTES = 64


class CallbackDataTooLongError(ValueError):
    """callback_data exceeds Telegram Bot API limit (64 bytes UTF-8)."""


def build_callback_data(*parts: str) -> str:
    """Join parts with ``:`` and enforce Telegram's 64-byte callback_data limit."""
    data = ":".join(str(p) for p in parts)
    size = len(data.encode("utf-8"))
    if size > TELEGRAM_CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataTooLongError(
            f"callback_data is {size} bytes "
            f"(max {TELEGRAM_CALLBACK_DATA_MAX_BYTES}): {data!r}"
        )
    return data


def validate_callback_data(data: str) -> str:
    """Validate a pre-built callback string (e.g. static prefix constants)."""
    size = len(data.encode("utf-8"))
    if size > TELEGRAM_CALLBACK_DATA_MAX_BYTES:
        raise CallbackDataTooLongError(
            f"callback_data is {size} bytes "
            f"(max {TELEGRAM_CALLBACK_DATA_MAX_BYTES}): {data!r}"
        )
    return data


def parse_callback_index(data: str, prefix: str) -> int:
    """Extract integer suffix from callback_data like ``prefix:42`` (pagination)."""
    suffix = data[len(prefix) + 1 :]
    return int(suffix)


def parse_callback_suffix(data: str, prefix: str) -> str:
    """Extract string suffix from callback_data like ``prefix:value`` (e.g. pubkey)."""
    return data[len(prefix) + 1 :]


def main_menu(is_admin: bool) -> ReplyKeyboardMarkup:
    """Persistent reply keyboard for registered operators."""
    rows = [
        [KeyboardButton(text=BTN_STATUS), KeyboardButton(text=BTN_CLIENTS)],
        [KeyboardButton(text=BTN_HELP)],
    ]
    if is_admin:
        rows.append([KeyboardButton(text=BTN_ADD_CLIENT)])
        rows.append(
            [KeyboardButton(text=BTN_DRIFT), KeyboardButton(text=BTN_OPERATORS)]
        )
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)


def client_actions_keyboard(pubkey: str, *, is_admin: bool) -> InlineKeyboardMarkup:
    """Inline actions for a single client row in /listclients."""
    row = [
        InlineKeyboardButton(
            text="📊 Статистика",
            callback_data=build_callback_data(CB_STATS, pubkey),
        )
    ]
    if is_admin:
        row.extend(
            [
                InlineKeyboardButton(
                    text="🔄 Ротация",
                    callback_data=build_callback_data(CB_ROTATE_ASK, pubkey),
                ),
                InlineKeyboardButton(
                    text="🗑 Удалить",
                    callback_data=build_callback_data(CB_REMOVE_ASK, pubkey),
                ),
            ]
        )
    return InlineKeyboardMarkup(inline_keyboard=[row])


def rotate_confirm_keyboard(pubkey: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Подтвердить",
                    callback_data=build_callback_data(CB_ROTATE_CONFIRM, pubkey),
                ),
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_ROTATE_CANCEL),
                ),
            ]
        ]
    )


def remove_confirm_keyboard(pubkey: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Удалить",
                    callback_data=build_callback_data(CB_REMOVE_CONFIRM, pubkey),
                ),
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_REMOVE_CANCEL),
                ),
            ]
        ]
    )


def clients_pagination_keyboard(page: int, total_pages: int) -> InlineKeyboardMarkup | None:
    """Navigation row for paginated client list. None if single page."""
    if total_pages <= 1:
        return None
    row = []
    if page > 0:
        row.append(
            InlineKeyboardButton(
                text="◀️ Назад",
                callback_data=build_callback_data(CB_CLIENTS_PAGE, page - 1),
            )
        )
    row.append(
        InlineKeyboardButton(
            text=f"{page + 1}/{total_pages}",
            callback_data=build_callback_data(CB_CLIENTS_PAGE, page),
        )
    )
    if page < total_pages - 1:
        row.append(
            InlineKeyboardButton(
                text="▶️ Вперёд",
                callback_data=build_callback_data(CB_CLIENTS_PAGE, page + 1),
            )
        )
    return InlineKeyboardMarkup(inline_keyboard=[row])


def add_client_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_ADDCLIENT_CANCEL),
                )
            ]
        ]
    )


def operator_row_keyboard(user_id: int, role: str) -> Optional[InlineKeyboardMarkup]:
    """Inline actions for a single operator row. Superadmin has no remove button."""
    if role == "superadmin":
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🗑 Удалить",
                    callback_data=build_callback_data(CB_USER_REMOVE_ASK, user_id),
                )
            ]
        ]
    )


def operators_footer_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="➕ Добавить оператора",
                    callback_data=validate_callback_data(CB_USER_ADD_START),
                )
            ]
        ]
    )


def add_user_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_USER_ADD_CANCEL),
                )
            ]
        ]
    )


def add_user_pick_keyboard() -> ReplyKeyboardMarkup:
    """Reply keyboard with Telegram user picker (Bot API request_users)."""
    return ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(
                    text=BTN_PICK_USER,
                    request_users=KeyboardButtonRequestUsers(
                        request_id=ADD_USER_REQUEST_ID,
                        user_is_bot=False,
                        max_quantity=1,
                    ),
                )
            ]
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
    )


def add_user_role_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="admin",
                    callback_data=build_callback_data(CB_USER_ADD_ROLE, user_id, "admin"),
                ),
                InlineKeyboardButton(
                    text="user",
                    callback_data=build_callback_data(CB_USER_ADD_ROLE, user_id, "user"),
                ),
            ],
            [
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_USER_ADD_CANCEL),
                )
            ],
        ]
    )


def operator_remove_confirm_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Удалить",
                    callback_data=build_callback_data(CB_USER_REMOVE_CONFIRM, user_id),
                ),
                InlineKeyboardButton(
                    text="❌ Отмена",
                    callback_data=validate_callback_data(CB_USER_REMOVE_CANCEL),
                ),
            ]
        ]
    )


_CALLBACK_PREFIXES = (
    CB_STATS,
    CB_ROTATE_ASK,
    CB_ROTATE_CONFIRM,
    CB_ROTATE_CANCEL,
    CB_REMOVE_ASK,
    CB_REMOVE_CONFIRM,
    CB_REMOVE_CANCEL,
    CB_CLIENTS_PAGE,
    CB_ADDCLIENT_CANCEL,
    CB_USER_ADD_START,
    CB_USER_ADD_CANCEL,
    CB_USER_ADD_ROLE,
    CB_USER_REMOVE_ASK,
    CB_USER_REMOVE_CONFIRM,
    CB_USER_REMOVE_CANCEL,
)

for _prefix in _CALLBACK_PREFIXES:
    validate_callback_data(_prefix)
