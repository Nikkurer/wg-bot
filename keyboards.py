"""Telegram keyboards and callback_data conventions.

Client actions use global index into sorted client list (not name) to stay
within Telegram callback_data 64-byte limit.

Callback prefixes:
  stats:{idx}             — client traffic stats
  rotate:ask:{idx}        — prompt key rotation confirm
  rotate:confirm:{idx}    — execute key rotation
  rotate:cancel           — cancel rotation dialog
  remove:ask:{idx}        — prompt client removal confirm
  remove:confirm:{idx}    — execute client removal
  remove:cancel           — cancel removal dialog
  clients:page:{n}        — paginated client list
  addclient:cancel        — cancel add-client dialog (FSM)
  useradd:* / userremove:* — operator management
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


def parse_callback_index(data: str, prefix: str) -> int:
    """Extract integer index from callback_data like ``prefix:42``."""
    suffix = data[len(prefix) + 1 :]
    return int(suffix)


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


def client_actions_keyboard(idx: int, *, is_admin: bool) -> InlineKeyboardMarkup:
    """Inline actions for a single client row in /listclients."""
    row = [
        InlineKeyboardButton(text="📊 Статистика", callback_data=f"{CB_STATS}:{idx}")
    ]
    if is_admin:
        row.extend(
            [
                InlineKeyboardButton(
                    text="🔄 Ротация", callback_data=f"{CB_ROTATE_ASK}:{idx}"
                ),
                InlineKeyboardButton(
                    text="🗑 Удалить", callback_data=f"{CB_REMOVE_ASK}:{idx}"
                ),
            ]
        )
    return InlineKeyboardMarkup(inline_keyboard=[row])


def rotate_confirm_keyboard(idx: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Подтвердить",
                    callback_data=f"{CB_ROTATE_CONFIRM}:{idx}",
                ),
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_ROTATE_CANCEL
                ),
            ]
        ]
    )


def remove_confirm_keyboard(idx: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Удалить", callback_data=f"{CB_REMOVE_CONFIRM}:{idx}"
                ),
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_REMOVE_CANCEL
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
                text="◀️ Назад", callback_data=f"{CB_CLIENTS_PAGE}:{page - 1}"
            )
        )
    row.append(
        InlineKeyboardButton(
            text=f"{page + 1}/{total_pages}", callback_data=f"{CB_CLIENTS_PAGE}:{page}"
        )
    )
    if page < total_pages - 1:
        row.append(
            InlineKeyboardButton(
                text="▶️ Вперёд", callback_data=f"{CB_CLIENTS_PAGE}:{page + 1}"
            )
        )
    return InlineKeyboardMarkup(inline_keyboard=[row])


def add_client_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_ADDCLIENT_CANCEL
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
                    callback_data=f"{CB_USER_REMOVE_ASK}:{user_id}",
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
                    callback_data=CB_USER_ADD_START,
                )
            ]
        ]
    )


def add_user_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_USER_ADD_CANCEL
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
                    callback_data=f"{CB_USER_ADD_ROLE}:{user_id}:admin",
                ),
                InlineKeyboardButton(
                    text="user",
                    callback_data=f"{CB_USER_ADD_ROLE}:{user_id}:user",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_USER_ADD_CANCEL
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
                    callback_data=f"{CB_USER_REMOVE_CONFIRM}:{user_id}",
                ),
                InlineKeyboardButton(
                    text="❌ Отмена", callback_data=CB_USER_REMOVE_CANCEL
                ),
            ]
        ]
    )
