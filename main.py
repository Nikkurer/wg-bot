import argparse
import asyncio
import datetime
import html
import io
import logging
import os
import sys
import traceback
from functools import partial
from typing import Optional

import qrcode
from aiogram import Bot, Dispatcher, F
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandObject, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    BotCommandScopeChat,
    BotCommandScopeDefault,
    BufferedInputFile,
    CallbackQuery,
    FSInputFile,
    Message,
    ReplyKeyboardRemove,
)
from bootstrap import enrich_from_wg_admin
from client_list import (
    CLIENTS_PAGE_SIZE,
    client_by_name,
    client_by_pubkey,
    paginate_clients,
    sort_clients,
)
from client_manager import ClientManagerError
from client_ownership import (
    can_manage_client,
    can_view_client,
    filter_clients_for_actor,
    format_owner_label,
)
from config import BotConfig, ConfigError, load_config
from keyboards import (
    ADMIN_MENU_BUTTONS,
    BTN_ADD_CLIENT,
    BTN_CLIENTS,
    BTN_DRIFT,
    BTN_HELP,
    BTN_OPERATORS,
    BTN_STATUS,
    CB_ADDCLIENT_CANCEL,
    CB_REMOVE_ASK,
    CB_REMOVE_CANCEL,
    CB_REMOVE_CONFIRM,
    CB_ROTATE_ASK,
    CB_ROTATE_CANCEL,
    CB_ROTATE_CONFIRM,
    CB_CLIENTS_PAGE,
    CB_STATS,
    CB_USER_ADD_CANCEL,
    CB_USER_ADD_ROLE,
    CB_USER_ADD_START,
    CB_USER_REMOVE_ASK,
    CB_USER_REMOVE_CANCEL,
    CB_USER_REMOVE_CONFIRM,
    add_client_cancel_keyboard,
    add_user_cancel_keyboard,
    add_user_pick_keyboard,
    add_user_role_keyboard,
    client_actions_keyboard,
    clients_pagination_keyboard,
    main_menu,
    parse_callback_index,
    parse_callback_suffix,
    operator_remove_confirm_keyboard,
    operator_row_keyboard,
    operators_footer_keyboard,
    remove_confirm_keyboard,
    rotate_confirm_keyboard,
)
from operator_add import (
    ADD_USER_REQUEST_ID,
    contact_user_id_or_error,
    format_operator_display,
    format_person_name,
    pending_profile_from_fsm,
)
from service import ClientService, ClientServiceError
from states import AddClientStates, AddUserStates
from status_format import format_status_error, format_status_message
from users import UserManager
from wg_admin_client import DriftReport, WgAdminClient, WgAdminError

# --- Logging setup ---
infoLog = logging.getLogger("wg_bot_info")
debugLog = logging.getLogger("wg_bot_debug")


def _debug_from_env() -> bool:
    return os.environ.get("DEBUG", "").strip().lower() in ("1", "true", "yes", "on")


def setup_logging(verbosity):
    """Настраивает систему логирования для бота.

    Создаёт два обработчика:
    - StreamHandler для вывода INFO и выше в stdout
    - FileHandler для записи DEBUG и выше в файл wg_bot_debug.log

    Args:
        verbosity (int): Уровень детализации логирования:
            0 - INFO и выше (по умолчанию)
            1 - INFO и выше (то же самое)
            2+ - DEBUG и выше
            Также DEBUG=1 в окружении даёт уровень 2+.
    """
    # Определяем уровни логирования
    # По умолчанию (verbosity=0) выводим INFO, чтобы видеть основные события
    console_level = (
        logging.DEBUG
        if verbosity >= 2
        else logging.INFO  # По умолчанию INFO, а не WARNING
    )
    file_level = logging.DEBUG

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Настраиваем root логгер
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # Всегда DEBUG для root, фильтрация на уровне handlers

    # Удаляем существующие обработчики, чтобы избежать дублирования
    root.handlers.clear()

    # Обработчик для консоли
    ch_console = logging.StreamHandler(sys.stdout)
    ch_console.setLevel(console_level)
    ch_console.setFormatter(formatter)
    root.addHandler(ch_console)

    # Обработчик для файла (не падаем, если volume недоступен для записи)
    log_dir = os.environ.get("WGBOT_LOG_DIR", ".")
    log_path = os.path.join(log_dir, "wg_bot_debug.log")
    try:
        os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(log_path)
        fh.setLevel(file_level)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError as e:
        print(
            f"Warning: file logging disabled ({log_path}): {e}",
            file=sys.stderr,
        )

    # Настраиваем конкретные логгеры
    infoLog.setLevel(logging.DEBUG)
    debugLog.setLevel(logging.DEBUG)
    infoLog.propagate = True
    debugLog.propagate = True


# --- Config loader (see config.py) ---


# --- helpers ---
def format_bytes(val: int) -> str:
    """Форматирует количество байт в человекочитаемый вид."""
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(val)
    for u in units:
        if size < 1024:
            return f"{size:.2f} {u}"
        size /= 1024
    return f"{size:.2f} PiB"


def format_handshake(ts: Optional[int]) -> str:
    """Преобразует timestamp последнего handshake в человекочитаемый вид."""
    if not ts:
        return "never"
    dt = datetime.datetime.fromtimestamp(ts)
    ago = datetime.datetime.now() - dt
    minutes, seconds = divmod(ago.seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m ago"
    return f"{minutes}m {seconds}s ago"


def format_drift_report(report: DriftReport) -> str:
    """Форматирует отчёт drift в текст для Telegram."""
    if report.in_sync:
        return "✅ Drift check: storage и WireGuard совпадают (in sync)."

    lines = ["⚠️ Drift detected — storage и WireGuard расходятся:", ""]

    if report.only_in_storage:
        lines.append("📦 Только в storage wg-admin:")
        for p in report.only_in_storage:
            ips = ", ".join(p.allowed_ips) or "—"
            lines.append(f"  • {p.public_key[:16]}... ({ips})")
        lines.append("")

    if report.only_in_wireguard:
        lines.append("🔌 Только в WireGuard runtime:")
        for p in report.only_in_wireguard:
            ips = ", ".join(p.allowed_ips) or "—"
            lines.append(f"  • {p.public_key[:16]}... ({ips})")
        lines.append("")

    if report.mismatch:
        lines.append("🔀 Расхождение полей:")
        for m in report.mismatch:
            s_ips = ", ".join(m.storage.allowed_ips) or "—"
            w_ips = ", ".join(m.wireguard.allowed_ips) or "—"
            lines.append(
                f"  • {m.public_key[:16]}...\n"
                f"    storage: {s_ips}\n"
                f"    wireguard: {w_ips}"
            )

    return "\n".join(lines)


def mask_secret(s, keep=4):
    """Маскирует секретную строку, оставляя видимыми только начало и конец.

    Args:
        s (str): Секретная строка для маскировки.
        keep (int, optional): Количество символов для отображения в начале
            и конце. По умолчанию 4.

    Returns:
        str: Маскированная строка в формате "XXXX...XXXX" или "<REDACTED>"
            если строка слишком короткая, или "<empty>" если пустая.
    """
    if not s:
        return "<empty>"
    if len(s) <= keep * 2:
        return "<REDACTED>"
    return s[:keep] + "..." + s[-keep:]


async def send_client_conf_and_qr(
    message: Message, name: str, conf_path: str, conf_text: str, client_ip: str
):
    """Отправляет .conf и QR-код клиента."""
    await message.answer_document(
        document=FSInputFile(conf_path, filename=f"{name}.conf"),
        caption=f"Client '{name}' created with IP {client_ip}",
    )
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
    qr.add_data(conf_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)
    photo_file = BufferedInputFile(bio.getvalue(), filename=f"{name}.png")
    await message.answer_photo(photo=photo_file, caption=f"QR для клиента '{name}'")


async def create_and_send_client(
    message: Message, name: str, service: ClientService, *, actor_id: int
) -> None:
    """Создаёт клиента и отправляет .conf + QR."""
    try:
        res = await service.create_client(name, actor_id=actor_id)
        await send_client_conf_and_qr(
            message,
            name,
            res.record.conf_path,
            res.conf_text,
            res.record.client_ip,
        )
    except ClientServiceError as e:
        infoLog.error("ClientServiceError: %s", e)
        await message.answer("Ошибка при добавлении клиента.")
    except Exception as e:
        infoLog.error("Unexpected error: %s", traceback.format_exc())
        await message.answer(f"Unexpected error: {e}")


async def prompt_add_client(message: Message, state: FSMContext):
    """Запускает диалог добавления клиента (FSM)."""
    await state.set_state(AddClientStates.waiting_for_name)
    await message.answer(
        "Введите имя нового клиента.\n"
        "Допустимы: латиница, цифры, `-`, `_` (например: `alice` или `phone-2`).",
        reply_markup=add_client_cancel_keyboard(),
    )


# Команды для обычных пользователей (роль user) и всех незарегистрированных.
VIEWER_COMMANDS = [
    BotCommand(command="status", description="Показать статус WireGuard"),
    BotCommand(command="listclients", description="Показать список клиентов"),
    BotCommand(command="help", description="Справка по командам"),
]

# Полный набор для admin/superadmin (без команд с параметрами — они через кнопки/slash).
ADMIN_COMMANDS = [
    BotCommand(command="status", description="Показать статус WireGuard"),
    BotCommand(command="listclients", description="Показать список клиентов"),
    BotCommand(command="drift", description="Проверить drift storage vs WireGuard"),
    BotCommand(command="listusers", description="Показать пользователей"),
    BotCommand(command="help", description="Справка по командам"),
]


async def apply_command_menus(bot: Bot, um: UserManager):
    """Устанавливает меню команд по ролям через Telegram command scopes.

    Глобальный дефолт — минимальный набор (VIEWER_COMMANDS). Для каждого
    известного оператора задаётся персональный scope в его личном чате:
    admin/superadmin видят полный список, user — набор для просмотра.

    Args:
        bot (Bot): Экземпляр Telegram бота.
        um (UserManager): Менеджер пользователей для определения ролей.
    """
    await bot.set_my_commands(VIEWER_COMMANDS, scope=BotCommandScopeDefault())
    for u in um.list_users():
        cmds = ADMIN_COMMANDS if u["role"] in ("admin", "superadmin") else VIEWER_COMMANDS
        try:
            await bot.set_my_commands(
                cmds, scope=BotCommandScopeChat(chat_id=u["id"])
            )
        except TelegramBadRequest:
            # Чат с ботом ещё не открыт — персональный scope применится
            # при следующем рестарте/adduser после того, как юзер нажмёт /start.
            debugLog.debug("Skip command scope for chat %s (not started)", u["id"])


# --- Handlers ---
async def cmd_start(message: Message, um: UserManager):
    """Приветствие и reply-меню по роли."""
    if not um.is_user(message.from_user.id):
        await message.answer(
            "Access denied.\n"
            "Обратитесь к администратору, чтобы получить доступ к боту."
        )
        return
    user = message.from_user
    um.update_user_profile(
        user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        username=user.username,
    )
    is_admin = um.is_admin(message.from_user.id)
    await message.answer(
        "WireGuard management bot.\n\n"
        "Используйте кнопки меню ниже или команду /help.\n"
        "Если меню пропало — отправьте /start.",
        reply_markup=main_menu(is_admin=is_admin, is_user=True),
    )


async def handle_menu(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Маршрутизация нажатий reply-меню к существующим handlers."""
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return

    text = message.text
    await state.clear()

    if text == BTN_STATUS:
        await cmd_status(message, wg_admin, cfg, service, um)
    elif text == BTN_CLIENTS:
        await cmd_listclients(message, service, um)
    elif text == BTN_HELP:
        await cmd_help(message, um)
    elif text == BTN_ADD_CLIENT:
        if not um.is_user(message.from_user.id):
            await message.answer("Access denied.")
            return
        await prompt_add_client(message, state)
    elif text == BTN_DRIFT:
        await cmd_drift(message, wg_admin, um)
    elif text == BTN_OPERATORS:
        await cmd_listusers(message, um)


async def sorted_clients(service: ClientService) -> list:
    return sort_clients(await service.list_clients_merged())


async def find_client_by_pubkey(service: ClientService, pubkey: str) -> dict | None:
    return client_by_pubkey(await sorted_clients(service), pubkey)


def format_client_card(c: dict, *, owner_label: str | None = None) -> str:
    label = c.get("display_name", c["name"])
    ip_display = c["ip"]
    if c.get("ip_v6"):
        ip_display = f"{c['ip']}, {c['ip_v6']}"
    local_mark = "" if c.get("has_local_conf") else " ⚠️ no local conf"
    text = (
        f"• {label} — {ip_display} "
        f"(pubkey: {c['pubkey'][:8]}...){local_mark}\n"
    )
    if owner_label is not None:
        text += f"  👤 Владелец: {owner_label}\n"
    return text


async def send_clients_page(
    message: Message,
    service: ClientService,
    um: UserManager,
    page: int = 0,
):
    """Отправляет страницу списка клиентов с пагинацией."""
    actor_id = message.from_user.id
    all_clients = await sorted_clients(service)
    clients = filter_clients_for_actor(all_clients, actor_id, um)
    if not clients:
        empty = "Нет ваших клиентов." if not um.is_admin(actor_id) else "Нет клиентов."
        await message.answer(empty)
        return

    page_clients, page, total_pages = paginate_clients(clients, page)
    show_owner = um.is_admin(actor_id)

    for c in page_clients:
        owner_label = format_owner_label(c.get("owner"), um) if show_owner else None
        await message.answer(
            format_client_card(c, owner_label=owner_label),
            reply_markup=client_actions_keyboard(
                c["pubkey"],
                can_manage=can_manage_client(actor_id, um, c),
                has_local_conf=c.get("has_local_conf", True),
            ),
        )

    nav = clients_pagination_keyboard(page, total_pages)
    if nav:
        await message.answer(
            f"Клиенты — страница {page + 1}/{total_pages} "
            f"(всего {len(clients)}, по {CLIENTS_PAGE_SIZE})",
            reply_markup=nav,
        )


async def prompt_rotate(
    message: Message, service: ClientService, pubkey: str, um: UserManager, *, actor_id: int
):
    """Запрос подтверждения ротации ключей клиента."""
    client = await find_client_by_pubkey(service, pubkey)
    if not client:
        await message.answer("Client not found.")
        return
    if not can_manage_client(actor_id, um, client):
        await message.answer("Access denied.")
        return
    name = client.get("display_name", client["name"])
    if not client.get("has_local_conf") or not client.get("storage_name"):
        await message.answer(
            f"⚠️ У клиента '{name}' нет локального conf — ротация недоступна."
        )
        return
    await message.answer(
        f"⚠️ Ротация ключей для клиента '{name}'?\n\n"
        "После подтверждения старый .conf и QR перестанут работать.",
        reply_markup=rotate_confirm_keyboard(pubkey),
    )


async def prompt_remove(
    message: Message, service: ClientService, pubkey: str, um: UserManager, *, actor_id: int
):
    """Запрос подтверждения удаления клиента."""
    client = await find_client_by_pubkey(service, pubkey)
    if not client:
        await message.answer("Client not found.")
        return
    if not can_manage_client(actor_id, um, client):
        await message.answer("Access denied.")
        return
    name = client.get("display_name", client["name"])
    files_note = (
        "Peer будет снят с сервера, локальные файлы удалены."
        if client.get("has_local_conf")
        else "Peer будет снят с сервера (локальных файлов нет)."
    )
    await message.answer(
        f"⚠️ Удалить клиента '{name}'?\n\n{files_note}",
        reply_markup=remove_confirm_keyboard(pubkey),
    )


async def prompt_rotate_by_name(
    message: Message, service: ClientService, um: UserManager, name: str, *, actor_id: int
):
    try:
        service.clients.validate_name(name)
    except ClientManagerError:
        await message.answer(f"Invalid client name: {name!r}")
        return
    clients = filter_clients_for_actor(await sorted_clients(service), actor_id, um)
    client = client_by_name(clients, name)
    if client is None:
        await message.answer(f"Client '{name}' not found.")
        return
    await prompt_rotate(message, service, client["pubkey"], um, actor_id=actor_id)


async def prompt_remove_by_name(
    message: Message, service: ClientService, um: UserManager, name: str, *, actor_id: int
):
    try:
        service.clients.validate_name(name)
    except ClientManagerError:
        await message.answer(f"Invalid client name: {name!r}")
        return
    clients = filter_clients_for_actor(await sorted_clients(service), actor_id, um)
    client = client_by_name(clients, name)
    if client is None:
        await message.answer(f"Client '{name}' not found.")
        return
    await prompt_remove(message, service, client["pubkey"], um, actor_id=actor_id)


async def cb_stats(callback: CallbackQuery, service: ClientService, um: UserManager):
    """Обработчик callback для просмотра статистики клиента."""
    if not um.is_user(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return

    try:
        pubkey = parse_callback_suffix(callback.data, CB_STATS)
        client = await find_client_by_pubkey(service, pubkey)
        if not client:
            await callback.answer("Client not found.", show_alert=True)
            return
        if not can_view_client(callback.from_user.id, um, client):
            await callback.answer("Access denied.", show_alert=True)
            return
        name = client.get("display_name", client["name"])
        ip_display = client["ip"]
        if client.get("ip_v6"):
            ip_display = f"{client['ip']}, {client['ip_v6']}"
        text = (
            f"📊 Статистика для {name}:\n\n"
            f"Endpoint: {client['endpoint'] or '—'}\n"
            f"IP: {ip_display}\n"
            f"Handshake: {format_handshake(client['latest_handshake'])}\n"
            f"RX: {format_bytes(client['transfer_rx'])}\n"
            f"TX: {format_bytes(client['transfer_tx'])}\n"
        )
        await callback.message.answer(text)
        await callback.answer()
    except ClientServiceError as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)


async def cmd_help(message: Message, um: UserManager):
    """Обработчик команды /help."""
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    lines = [
        "WireGuard management bot:\n",
        "Меню:",
        f"  {BTN_STATUS} — статус VPN-сервера и сводка по клиентам",
        f"  {BTN_CLIENTS} — список клиентов (на карточке — статистика)",
        f"  {BTN_HELP} — эта справка",
        f"  {BTN_ADD_CLIENT} — создать нового клиента",
    ]
    if um.is_admin(message.from_user.id):
        lines += [
            f"  {BTN_DRIFT} — проверка drift wg-admin vs WireGuard",
            f"  {BTN_OPERATORS} — список операторов (добавить / удалить; контакт или picker)",
            "",
            "На карточке клиента (admin): 🔄 Ротация, 🗑 Удалить; у user — только свои клиенты",
            "",
            "Slash-команды (fallback):",
            "  /addclient <name> — создать клиента",
            "  /removeclient <name> — удалить клиента",
            "  /rotateclient <name> — ротация ключей",
            "  /adduser <id> <admin|user> — добавить оператора (admin — только superadmin)",
            "  /removeuser <id> — удалить оператора",
        ]
    else:
        lines += [
            "",
            "На карточке своего клиента: 🔄 Ротация, 🗑 Удалить",
            "",
            "Slash-команды (fallback):",
            "  /addclient <name> — создать клиента",
            "  /removeclient <name> — удалить своего клиента",
            "  /rotateclient <name> — ротация ключей своего клиента",
        ]
    lines += ["", "Если кнопки меню не видны — отправьте /start."]
    is_admin = um.is_admin(message.from_user.id)
    await message.answer("\n".join(lines), reply_markup=main_menu(is_admin=is_admin, is_user=True))


async def cmd_status(
    message: Message,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Обработчик команды /status."""
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return

    actor_id = message.from_user.id
    is_admin = um.is_admin(actor_id)
    try:
        status = await wg_admin.interface_status()
        clients = await sorted_clients(service)
        if not is_admin:
            clients = filter_clients_for_actor(clients, actor_id, um)
        drift_report = None
        if is_admin:
            drift_report = await wg_admin.detect_drift()
        text = format_status_message(
            status=status,
            clients=clients,
            cfg=cfg,
            is_admin=is_admin,
            online_threshold_sec=cfg.status_online_threshold_sec,
            drift_report=drift_report,
        )
        await message.answer(text)
    except WgAdminError as e:
        infoLog.error("Status failed: %s", e)
        await message.answer(format_status_error(is_admin=is_admin, error=str(e)))
    except ClientServiceError as e:
        infoLog.error("Status failed: %s", e)
        await message.answer(format_status_error(is_admin=is_admin, error=str(e)))
    except Exception as e:
        infoLog.error("Status failed: %s", traceback.format_exc())
        await message.answer(format_status_error(is_admin=is_admin, error=str(e)))


async def cmd_addclient(
    message: Message, command: CommandObject, service: ClientService, um: UserManager
):
    """Обработчик команды /addclient.

    Создаёт нового клиента WireGuard и отправляет конфигурационный файл
    и QR-код пользователю.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументами.
        service (ClientService): Сервис управления клиентами через wg-admin.
        um (UserManager): Менеджер пользователей для проверки доступа.
    """
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer(
            f"Usage: /addclient <name>\n"
            f"Или нажмите {BTN_ADD_CLIENT} в меню."
        )
        return
    name = command.args.strip()
    await create_and_send_client(message, name, service, actor_id=message.from_user.id)


async def fsm_addclient_name(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Принимает имя клиента в диалоге добавления."""
    if not um.is_user(message.from_user.id):
        await state.clear()
        await message.answer("Access denied.")
        return

    if message.text in ADMIN_MENU_BUTTONS:
        await state.clear()
        await handle_menu(message, state, wg_admin, cfg, service, um)
        return

    name = message.text.strip()
    try:
        service.clients.validate_name(name)
    except ClientManagerError:
        await message.answer(
            "Неверное имя. Допустимы: латиница, цифры, `-`, `_`.\n"
            "Попробуйте ещё раз или нажмите ❌ Отмена."
        )
        return

    await state.clear()
    await create_and_send_client(message, name, service, actor_id=message.from_user.id)


async def cb_addclient_cancel(
    callback: CallbackQuery, state: FSMContext, um: UserManager
):
    """Отмена диалога добавления клиента."""
    if not um.is_user(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return
    await state.clear()
    await callback.message.edit_text("Добавление клиента отменено.")
    await callback.answer()


async def cmd_removeclient(
    message: Message, command: CommandObject, service: ClientService, um: UserManager
):
    """Обработчик команды /removeclient.

    Удаляет клиента WireGuard по имени.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументами.
        service (ClientService): Сервис управления клиентами через wg-admin.
        um (UserManager): Менеджер пользователей для проверки доступа.
    """
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer(
            "Usage: /removeclient <name>\n"
            f"Или откройте {BTN_CLIENTS} и нажмите 🗑 Удалить на карточке клиента."
        )
        return
    name = command.args.strip()
    await prompt_remove_by_name(message, service, um, name, actor_id=message.from_user.id)


async def cmd_listclients(message: Message, service: ClientService, um: UserManager):
    """Обработчик команды /listclients."""
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        await send_clients_page(message, service, um, page=0)
    except ClientServiceError as e:
        await message.answer(f"Failed: {e}")


async def cb_clients_page(
    callback: CallbackQuery, service: ClientService, um: UserManager
):
    """Переключение страницы списка клиентов."""
    if not um.is_user(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return
    page = parse_callback_index(callback.data, CB_CLIENTS_PAGE)
    try:
        await send_clients_page(callback.message, service, um, page=page)
        await callback.answer()
    except ClientServiceError as e:
        await callback.answer(str(e), show_alert=True)


async def cmd_drift(message: Message, wg_admin: WgAdminClient, um: UserManager):
    """Обработчик команды /drift."""
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        report = await wg_admin.detect_drift()
        await message.answer(format_drift_report(report))
    except WgAdminError as e:
        infoLog.error("Drift check failed: %s", e)
        await message.answer(f"❌ Ошибка drift check: {e}")


async def cmd_rotateclient(
    message: Message, command: CommandObject, service: ClientService, um: UserManager
):
    """Обработчик команды /rotateclient — запрос подтверждения."""
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer(
            "Usage: /rotateclient <name>\n"
            f"Или откройте {BTN_CLIENTS} и нажмите 🔄 Ротация на карточке клиента."
        )
        return
    name = command.args.strip()
    await prompt_rotate_by_name(message, service, um, name, actor_id=message.from_user.id)


async def cb_rotate_ask(
    callback: CallbackQuery, service: ClientService, um: UserManager
):
    """Кнопка «Ротация» на карточке клиента — показать confirm."""
    if not um.is_user(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return
    pubkey = parse_callback_suffix(callback.data, CB_ROTATE_ASK)
    await prompt_rotate(callback.message, service, pubkey, um, actor_id=callback.from_user.id)
    await callback.answer()


async def cb_rotate(callback: CallbackQuery, service: ClientService, um: UserManager):
    """Подтверждение или отмена ротации ключей."""
    actor_id = callback.from_user.id
    if not um.is_user(actor_id):
        await callback.answer("Access denied.", show_alert=True)
        return

    if callback.data == CB_ROTATE_CANCEL:
        await callback.message.edit_text("Ротация отменена.")
        await callback.answer()
        return

    if not callback.data.startswith(f"{CB_ROTATE_CONFIRM}:"):
        await callback.answer()
        return

    pubkey = parse_callback_suffix(callback.data, CB_ROTATE_CONFIRM)
    client = await find_client_by_pubkey(service, pubkey)
    if not client:
        await callback.answer("Client not found.", show_alert=True)
        return
    if not can_manage_client(actor_id, um, client):
        await callback.answer("Access denied.", show_alert=True)
        return
    name = client.get("display_name", client["name"])
    if not client.get("has_local_conf") or not client.get("storage_name"):
        await callback.answer(
            "Нет локального conf — ротация недоступна.", show_alert=True
        )
        return
    try:
        res = await service.rotate_client(
            client["storage_name"], actor_id=actor_id, um=um
        )
        await callback.message.edit_text(
            f"✅ Ключи клиента '{name}' обновлены.\n"
            "⚠️ Старый .conf недействителен — используйте новый файл и QR ниже."
        )
        await send_client_conf_and_qr(
            callback.message,
            name,
            res.record.conf_path,
            res.conf_text,
            res.record.client_ip,
        )
        await callback.answer()
    except ClientServiceError as e:
        infoLog.error("Rotate failed for %s: %s", name, e)
        await callback.answer(str(e), show_alert=True)


async def cb_remove(callback: CallbackQuery, service: ClientService, um: UserManager):
    """Запрос, подтверждение или отмена удаления клиента."""
    actor_id = callback.from_user.id
    if not um.is_user(actor_id):
        await callback.answer("Access denied.", show_alert=True)
        return

    if callback.data == CB_REMOVE_CANCEL:
        await callback.message.edit_text("Удаление отменено.")
        await callback.answer()
        return

    if callback.data.startswith(f"{CB_REMOVE_ASK}:"):
        pubkey = parse_callback_suffix(callback.data, CB_REMOVE_ASK)
        await prompt_remove(callback.message, service, pubkey, um, actor_id=actor_id)
        await callback.answer()
        return

    if not callback.data.startswith(f"{CB_REMOVE_CONFIRM}:"):
        await callback.answer()
        return

    pubkey = parse_callback_suffix(callback.data, CB_REMOVE_CONFIRM)
    client = await find_client_by_pubkey(service, pubkey)
    if not client:
        await callback.answer("Client not found.", show_alert=True)
        return
    if not can_manage_client(actor_id, um, client):
        await callback.answer("Access denied.", show_alert=True)
        return
    name = client.get("display_name", client["name"])
    try:
        await service.delete_client(client, actor_id=actor_id, um=um)
        await callback.message.edit_text(f"✅ Client '{name}' removed.")
        await callback.answer()
    except ClientServiceError as e:
        infoLog.error("Remove failed for %s: %s", name, e)
        await callback.answer(str(e), show_alert=True)
    except Exception as e:
        infoLog.error("Remove failed for %s: %s", name, traceback.format_exc())
        await callback.answer(f"Ошибка: {e}", show_alert=True)


# --- user management handlers ---
async def resolve_operator_label(bot: Bot, um: UserManager, user: dict) -> str:
    """Подпись оператора: сохранённый профиль, иначе get_chat, иначе id."""
    if user.get("first_name") or user.get("last_name") or user.get("username"):
        return format_operator_display(user)
    try:
        chat = await bot.get_chat(user["id"])
        if user.get("role") != "superadmin":
            um.update_user_profile(
                user["id"],
                first_name=chat.first_name,
                last_name=chat.last_name,
                username=chat.username,
            )
        return format_person_name(
            first_name=chat.first_name,
            last_name=chat.last_name,
            username=chat.username,
            user_id=user["id"],
        )
    except TelegramBadRequest:
        return str(user["id"])


async def do_add_user(
    bot: Bot,
    um: UserManager,
    user_id: int,
    role: str,
    actor_id: int,
    *,
    first_name: str | None = None,
    last_name: str | None = None,
    username: str | None = None,
) -> None:
    """Добавляет оператора и обновляет меню команд."""
    um.add_user(
        user_id,
        role,
        actor_id=actor_id,
        first_name=first_name,
        last_name=last_name,
        username=username,
    )
    await apply_command_menus(bot, um)


async def do_remove_user(bot: Bot, um: UserManager, user_id: int, *, actor_id: int) -> None:
    """Удаляет оператора и сбрасывает его меню команд."""
    um.remove_user(user_id, actor_id=actor_id)
    try:
        await bot.delete_my_commands(scope=BotCommandScopeChat(chat_id=user_id))
    except TelegramBadRequest:
        pass


async def prompt_add_user(message: Message, state: FSMContext):
    """Запускает диалог добавления оператора (FSM)."""
    await state.set_state(AddUserStates.waiting_for_id)
    await message.answer(
        "Добавление оператора — выберите способ:\n"
        "• нажмите «👤 Выбрать пользователя»\n"
        "• или 📎 → Контакт → выберите человека\n"
        "• или введите числовой Telegram ID",
        reply_markup=add_user_cancel_keyboard(),
    )
    await message.answer(
        "Выбор из Telegram:",
        reply_markup=add_user_pick_keyboard(),
    )


async def prompt_add_user_role(
    message: Message,
    state: FSMContext,
    um: UserManager,
    user_id: int,
    display: str | None = None,
    *,
    first_name: str | None = None,
    last_name: str | None = None,
    username: str | None = None,
):
    """Снимает picker-клавиатуру и предлагает выбрать роль."""
    if not (first_name or last_name or username):
        try:
            chat = await message.bot.get_chat(user_id)
            first_name = chat.first_name
            last_name = chat.last_name
            username = chat.username
        except TelegramBadRequest:
            pass

    await state.set_state(AddUserStates.waiting_for_role)
    await state.update_data(
        pending_user_id=user_id,
        pending_first_name=first_name,
        pending_last_name=last_name,
        pending_username=username,
    )
    label = display or format_operator_display(
        {
            "id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
        }
    )
    await message.answer("Пользователь выбран.", reply_markup=ReplyKeyboardRemove())
    await message.answer(
        f"Выберите роль для оператора {label}:",
        reply_markup=add_user_role_keyboard(
            user_id, allow_admin=um.is_superadmin(message.from_user.id)
        ),
    )


async def restore_admin_menu(
    message: Message,
    um: UserManager,
    text: str,
    *,
    user_id: int | None = None,
):
    """Восстанавливает reply-меню после диалога добавления оператора."""
    operator_id = user_id if user_id is not None else message.from_user.id
    is_admin = um.is_admin(operator_id)
    await message.answer(text, reply_markup=main_menu(is_admin=is_admin, is_user=True))


async def prompt_remove_user(
    message: Message, bot: Bot, um: UserManager, user_id: int, *, actor_id: int
):
    """Запрос подтверждения удаления оператора."""
    user = next((u for u in um.list_users() if u["id"] == user_id), {"id": user_id})
    if not um.can_manage_operator(actor_id, user):
        await message.answer("Недостаточно прав для удаления этого оператора.")
        return
    label = await resolve_operator_label(bot, um, user)
    await message.answer(
        f"⚠️ Удалить оператора {label}?\n\n"
        "Пользователь потеряет доступ к боту.",
        reply_markup=operator_remove_confirm_keyboard(user_id),
    )


async def cmd_listusers(message: Message, um: UserManager):
    """Список операторов с inline-кнопками управления."""
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    users = um.list_users()
    if not users:
        await message.answer(
            "Нет операторов.",
            reply_markup=operators_footer_keyboard(),
        )
        return
    actor_id = message.from_user.id
    for u in users:
        label = await resolve_operator_label(message.bot, um, u)
        text = f"👤 {label} — {u['role']}"
        kb = operator_row_keyboard(
            u["id"], u["role"], allow_remove=um.can_manage_operator(actor_id, u)
        )
        await message.answer(text, reply_markup=kb)
    await message.answer(
        "Управление операторами:",
        reply_markup=operators_footer_keyboard(),
    )


async def cmd_adduser(message: Message, command: CommandObject, um: UserManager):
    """Обработчик команды /adduser.

    Добавляет нового пользователя бота с указанной ролью.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументами (id и роль).
        um (UserManager): Менеджер пользователей.
    """
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer(
            "Usage: /adduser <id> <role>\n"
            f"Или откройте {BTN_OPERATORS} и нажмите ➕ Добавить оператора."
        )
        return
    try:
        user_id_str, role = command.args.split(maxsplit=1)
        await do_add_user(message.bot, um, int(user_id_str), role, message.from_user.id)
        await message.answer(f"✅ Пользователь {user_id_str} добавлен с ролью {role}.")
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")


async def fsm_adduser_id(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Принимает Telegram ID в диалоге добавления оператора."""
    if not um.is_admin(message.from_user.id):
        await state.clear()
        await message.answer("Access denied.")
        return

    if message.text in ADMIN_MENU_BUTTONS:
        await state.clear()
        await handle_menu(message, state, wg_admin, cfg, service, um)
        return

    text = message.text.strip()
    if not text.isdigit():
        await message.answer(
            "Введите числовой Telegram ID.\n"
            "Попробуйте ещё раз или нажмите ❌ Отмена."
        )
        return

    user_id = int(text)
    await prompt_add_user_role(message, state, um, user_id)


async def fsm_adduser_contact(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Принимает контакт в диалоге добавления оператора."""
    if not um.is_admin(message.from_user.id):
        await state.clear()
        await message.answer("Access denied.")
        return

    user_id, error = contact_user_id_or_error(message.contact.user_id)
    if error:
        await message.answer(
            f"{error}\nПопробуйте другой способ или нажмите ❌ Отмена."
        )
        return

    display = format_person_name(
        first_name=message.contact.first_name,
        last_name=message.contact.last_name,
        user_id=user_id,
    )
    await prompt_add_user_role(
        message,
        state,
        um,
        user_id,
        display,
        first_name=message.contact.first_name,
        last_name=message.contact.last_name,
    )


async def fsm_adduser_shared(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Принимает пользователя из Telegram user picker (request_users)."""
    if not um.is_admin(message.from_user.id):
        await state.clear()
        await message.answer("Access denied.")
        return

    shared = message.users_shared
    if not shared or shared.request_id != ADD_USER_REQUEST_ID:
        return
    if not shared.users:
        await message.answer("Пользователь не выбран. Попробуйте ещё раз.")
        return

    user = shared.users[0]
    display = format_person_name(
        first_name=user.first_name,
        last_name=user.last_name,
        username=user.username,
        user_id=user.user_id,
    )
    await prompt_add_user_role(
        message,
        state,
        um,
        user.user_id,
        display,
        first_name=user.first_name,
        last_name=user.last_name,
        username=user.username,
    )


async def fsm_adduser_user_shared(
    message: Message,
    state: FSMContext,
    wg_admin: WgAdminClient,
    cfg: BotConfig,
    service: ClientService,
    um: UserManager,
):
    """Fallback для user picker, если клиент прислал user_shared без имён."""
    if not um.is_admin(message.from_user.id):
        await state.clear()
        await message.answer("Access denied.")
        return

    shared = message.user_shared
    if not shared or shared.request_id != ADD_USER_REQUEST_ID:
        return

    await prompt_add_user_role(message, state, um, shared.user_id)


async def cb_useradd(callback: CallbackQuery, state: FSMContext, um: UserManager):
    """Старт, выбор роли или отмена добавления оператора."""
    if not um.is_admin(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return

    if callback.data == CB_USER_ADD_CANCEL:
        await state.clear()
        await callback.message.edit_text("Добавление оператора отменено.")
        await restore_admin_menu(
            callback.message,
            um,
            "Меню восстановлено.",
            user_id=callback.from_user.id,
        )
        await callback.answer()
        return

    if callback.data == CB_USER_ADD_START:
        await prompt_add_user(callback.message, state)
        await callback.answer()
        return

    if callback.data.startswith(f"{CB_USER_ADD_ROLE}:"):
        payload = callback.data[len(f"{CB_USER_ADD_ROLE}:") :]
        user_id_str, role = payload.split(":", 1)
        user_id = int(user_id_str)
        data = await state.get_data()
        profile = pending_profile_from_fsm(data, user_id)
        try:
            await do_add_user(
                callback.message.bot,
                um,
                user_id,
                role,
                callback.from_user.id,
                first_name=profile.get("first_name"),
                last_name=profile.get("last_name"),
                username=profile.get("username"),
            )
            await state.clear()
            added = next(u for u in um.list_users() if u["id"] == user_id)
            label = format_operator_display(added)
            await callback.message.edit_text(
                f"✅ Оператор {label} добавлен с ролью {role}."
            )
            await restore_admin_menu(
                callback.message,
                um,
                "Новому оператору нужно написать боту /start.",
                user_id=callback.from_user.id,
            )
        except Exception as e:
            await callback.message.edit_text(f"❌ Ошибка: {e}")
        await callback.answer()
        return

    await callback.answer()


async def cb_userremove(callback: CallbackQuery, um: UserManager):
    """Запрос, подтверждение или отмена удаления оператора."""
    if not um.is_admin(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return

    if callback.data == CB_USER_REMOVE_CANCEL:
        await callback.message.edit_text("Удаление оператора отменено.")
        await callback.answer()
        return

    if callback.data.startswith(f"{CB_USER_REMOVE_ASK}:"):
        user_id = int(callback.data.split(":", 2)[2])
        await prompt_remove_user(
            callback.message, callback.message.bot, um, user_id, actor_id=callback.from_user.id
        )
        await callback.answer()
        return

    if not callback.data.startswith(f"{CB_USER_REMOVE_CONFIRM}:"):
        await callback.answer()
        return

    user_id = int(callback.data.split(":", 2)[2])
    try:
        user = next((u for u in um.list_users() if u["id"] == user_id), {"id": user_id})
        label = await resolve_operator_label(callback.message.bot, um, user)
        await do_remove_user(
            callback.message.bot, um, user_id, actor_id=callback.from_user.id
        )
        await callback.message.edit_text(f"✅ Оператор {label} удалён.")
        await callback.answer()
    except Exception as e:
        await callback.message.edit_text(f"❌ Ошибка: {e}")
        await callback.answer()


async def cmd_removeuser(message: Message, command: CommandObject, um: UserManager):
    """Обработчик команды /removeuser.

    Удаляет пользователя из списка пользователей бота.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументом (id пользователя).
        um (UserManager): Менеджер пользователей.
    """
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer(
            "Usage: /removeuser <id>\n"
            f"Или откройте {BTN_OPERATORS} и нажмите 🗑 Удалить на карточке оператора."
        )
        return
    try:
        removed_id = int(command.args.strip())
        await prompt_remove_user(
            message, message.bot, um, removed_id, actor_id=message.from_user.id
        )
    except ValueError:
        await message.answer("❌ Ошибка: ID должен быть числом.")


# --- main ---
async def main():
    """Главная функция бота.

    Инициализирует логирование, загружает конфигурацию, создаёт менеджеры
    и запускает Telegram бота с регистрацией всех обработчиков команд.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("-v", action="count", default=0)
    args = parser.parse_args()

    verbosity = max(args.v, 2 if _debug_from_env() else 0)
    setup_logging(verbosity)

    try:
        bot_cfg = load_config(args.config)
    except ConfigError as e:
        infoLog.error(f"Config error: {e}")
        sys.exit(1)

    infoLog.info("Config loaded")
    debugLog.debug(
        f"Config details: WG={bot_cfg.wg_interface or '?'} DIR={bot_cfg.client_dir} "
        f"SUBNET={bot_cfg.wg_subnet} TOKEN={mask_secret(bot_cfg.telegram_token)}"
    )

    um = UserManager(bot_cfg.users_file, superadmins=bot_cfg.allowed_users)
    wg_admin = WgAdminClient(bot_cfg.wg_admin_socket)
    try:
        bot_cfg = await enrich_from_wg_admin(bot_cfg, wg_admin, logger=infoLog)
    except ConfigError as e:
        infoLog.error(f"Bootstrap error: {e}")
        await wg_admin.close()
        sys.exit(1)
    service = ClientService(bot_cfg, wg_admin)

    bot = Bot(token=bot_cfg.telegram_token)
    dp = Dispatcher(storage=MemoryStorage())

    dp.message.register(partial(cmd_start, um=um), Command("start"))
    dp.message.register(partial(cmd_help, um=um), Command("help"))
    dp.message.register(
        partial(cmd_status, wg_admin=wg_admin, cfg=bot_cfg, service=service, um=um),
        Command("status"),
    )
    dp.message.register(partial(cmd_addclient, service=service, um=um), Command("addclient"))
    dp.message.register(
        partial(cmd_removeclient, service=service, um=um), Command("removeclient")
    )
    dp.message.register(
        partial(cmd_listclients, service=service, um=um), Command("listclients")
    )
    dp.message.register(partial(cmd_drift, wg_admin=wg_admin, um=um), Command("drift"))
    dp.message.register(
        partial(cmd_rotateclient, service=service, um=um), Command("rotateclient")
    )

    dp.message.register(partial(cmd_listusers, um=um), Command("listusers"))
    dp.message.register(partial(cmd_adduser, um=um), Command("adduser"))
    dp.message.register(partial(cmd_removeuser, um=um), Command("removeuser"))

    dp.message.register(
        partial(
            fsm_addclient_name,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        StateFilter(AddClientStates.waiting_for_name),
        F.text,
    )

    dp.message.register(
        partial(
            fsm_adduser_id,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        StateFilter(AddUserStates.waiting_for_id),
        F.text,
    )

    dp.message.register(
        partial(
            fsm_adduser_contact,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        StateFilter(AddUserStates.waiting_for_id),
        F.contact,
    )

    dp.message.register(
        partial(
            fsm_adduser_shared,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        StateFilter(AddUserStates.waiting_for_id),
        F.users_shared,
    )

    dp.message.register(
        partial(
            fsm_adduser_user_shared,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        StateFilter(AddUserStates.waiting_for_id),
        F.user_shared,
    )

    dp.message.register(
        partial(
            handle_menu,
            wg_admin=wg_admin,
            cfg=bot_cfg,
            service=service,
            um=um,
        ),
        F.text.in_(ADMIN_MENU_BUTTONS),
    )

    dp.callback_query.register(
        partial(cb_stats, service=service, um=um), F.data.startswith("stats:")
    )
    dp.callback_query.register(
        partial(cb_clients_page, service=service, um=um),
        F.data.startswith(f"{CB_CLIENTS_PAGE}:"),
    )
    dp.callback_query.register(
        partial(cb_rotate_ask, service=service, um=um),
        F.data.startswith(f"{CB_ROTATE_ASK}:"),
    )
    dp.callback_query.register(
        partial(cb_rotate, service=service, um=um), F.data.startswith("rotate:")
    )
    dp.callback_query.register(
        partial(cb_remove, service=service, um=um), F.data.startswith("remove:")
    )
    dp.callback_query.register(
        partial(cb_addclient_cancel, um=um), F.data == CB_ADDCLIENT_CANCEL
    )
    dp.callback_query.register(
        partial(cb_useradd, um=um), F.data.startswith("useradd:")
    )
    dp.callback_query.register(
        partial(cb_userremove, um=um), F.data.startswith("userremove:")
    )

    await apply_command_menus(bot, um)
    infoLog.info("Bot starting...")
    try:
        await dp.start_polling(bot)
    finally:
        await wg_admin.close()


if __name__ == "__main__":
    asyncio.run(main())
