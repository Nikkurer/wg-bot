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

import qrcode
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandObject
from aiogram.types import (
    BotCommand,
    BufferedInputFile,
    CallbackQuery,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from config import ConfigError, load_config
from service import ClientService, ClientServiceError
from users import UserManager
from wg_admin_client import WgAdminClient
from wg_manager import WGManager, WGManagerError

# --- Logging setup ---
infoLog = logging.getLogger("wg_bot_info")
debugLog = logging.getLogger("wg_bot_debug")


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

    # Обработчик для файла
    log_dir = os.environ.get("WGBOT_LOG_DIR", ".")
    log_path = os.path.join(log_dir, "wg_bot_debug.log")
    fh = logging.FileHandler(log_path)
    fh.setLevel(file_level)
    fh.setFormatter(formatter)
    root.addHandler(fh)

    # Настраиваем конкретные логгеры
    infoLog.setLevel(logging.DEBUG)
    debugLog.setLevel(logging.DEBUG)
    infoLog.propagate = True
    debugLog.propagate = True


# --- Config loader (see config.py) ---


# --- helpers ---
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


async def register_bot_commands(bot: Bot):
    """Регистрирует команды бота в Telegram.

    Устанавливает список команд, которые будут отображаться в меню
    команд бота при вводе "/".

    Args:
        bot (Bot): Экземпляр Telegram бота.
    """
    commands = [
        BotCommand(command="status", description="Показать статус WireGuard"),
        BotCommand(command="addclient", description="Добавить нового клиента"),
        BotCommand(command="removeclient", description="Удалить клиента"),
        BotCommand(command="listclients", description="Показать список клиентов"),
        BotCommand(
            command="syncconfig", description="Синхронизировать клиентов из конфига"
        ),
        BotCommand(command="help", description="Справка по командам"),
        BotCommand(command="listusers", description="Показать пользователей"),
        BotCommand(command="adduser", description="Добавить пользователя"),
        BotCommand(command="removeuser", description="Удалить пользователя"),
    ]
    await bot.set_my_commands(commands)


# --- Handlers ---
async def cb_stats(callback: CallbackQuery, wg: WGManager, um: UserManager):
    """Обработчик callback для просмотра статистики клиента.

    Обрабатывает нажатие на кнопку "📊 Статистика" в списке клиентов.

    Args:
        callback (CallbackQuery): Callback запрос от Telegram.
        wg (WGManager): Менеджер WireGuard.
        um (UserManager): Менеджер пользователей.
    """
    if not um.is_user(callback.from_user.id):
        await callback.answer("Access denied.", show_alert=True)
        return

    try:
        name = callback.data.split(":", 1)[1]
        stats = wg.peer_stats(name)
        text = (
            f"📊 Статистика для {name}:\n\n"
            f"Endpoint: {stats['endpoint']}\n"
            f"Allowed IPs: {stats['allowed_ips']}\n"
            f"Handshake: {stats['latest_handshake']}\n"
            f"RX: {stats['rx_bytes']} bytes\n"
            f"TX: {stats['tx_bytes']} bytes\n"
        )
        await callback.message.answer(text)
        await callback.answer()
    except Exception as e:
        await callback.answer(f"Ошибка: {e}", show_alert=True)


async def cmd_help(message: Message, wg: WGManager, um: UserManager):
    """Обработчик команды /help.

    Отправляет пользователю справку по доступным командам бота.

    Args:
        message (Message): Сообщение от пользователя.
        wg (WGManager): Менеджер WireGuard (не используется).
        um (UserManager): Менеджер пользователей для проверки доступа.
    """
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    await message.answer(
        "WireGuard management bot — команды:\n\n"
        "/status — показать статус\n"
        "/addclient <name> — создать клиента\n"
        "/removeclient <name> — удалить клиента\n"
        "/listclients — список клиентов\n"
        "/syncconfig — синхронизировать из конфигов\n"
        "/help — это сообщение\n"
    )


async def cmd_status(message: Message, wg: WGManager, um: UserManager):
    """Обработчик команды /status.

    Отправляет пользователю статус интерфейса WireGuard и список пиров
    с их статистикой.

    Args:
        message (Message): Сообщение от пользователя.
        wg (WGManager): Менеджер WireGuard.
        um (UserManager): Менеджер пользователей для проверки доступа.
    """

    def format_bytes(val: str) -> str:
        """Форматирует количество байт в человекочитаемый вид.

        Args:
            val (str): Количество байт в виде строки.

        Returns:
            str: Отформатированная строка (например, "1.23 MiB").
        """
        val = int(val)
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        size = float(val)
        for u in units:
            if size < 1024:
                return f"{size:.2f} {u}"
            size /= 1024
        return f"{size:.2f} PiB"

    def format_handshake(ts: str) -> str:
        """Преобразует timestamp последнего handshake в человекочитаемый вид.

        Args:
            ts (str): Unix timestamp в виде строки.

        Returns:
            str: Строка вида "Xm Ys ago" или "never" если timestamp равен 0.
        """
        ts = int(ts)
        if ts == 0:
            return "never"
        dt = datetime.datetime.fromtimestamp(ts)
        ago = datetime.datetime.now() - dt
        minutes, seconds = divmod(ago.seconds, 60)
        return f"{minutes}m {seconds}s ago"

    def parse_wg_dump(output: str) -> dict:
        """Парсит вывод команды `wg show dump`.

        Args:
            output (str): Многострочный вывод команды wg dump.

        Returns:
            dict: Словарь с распарсенными данными:
                - interface (dict): Информация об интерфейсе
                - peers (list): Список словарей с информацией о пирах
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return {}

        result = {"interface": {}, "peers": []}

        # интерфейс (первая строка)
        iface = lines[0].split("\t")
        result["interface"] = {
            "private_key": iface[0],
            "public_key": iface[1],
            "listen_port": iface[2],
            "fwmark": iface[3],
        }

        # остальные строки — клиенты
        for line in lines[1:]:
            cols = line.split("\t")
            peer = {
                "public_key": cols[0],
                "preshared_key": cols[1],
                "endpoint": cols[2],
                "allowed_ips": cols[3],
                "latest_handshake": format_handshake(cols[4]),
                "transfer_rx": format_bytes(cols[5]),
                "transfer_tx": format_bytes(cols[6]),
                "keepalive": cols[7],
            }
            result["peers"].append(peer)

        return result

    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        raw_output = wg.status()  # должен вызывать `wg show wg0 dump`
        parsed = parse_wg_dump(raw_output)

        text = [
            "🔐 Interface: <b>wg0</b>",
            f"📡 Port: {parsed['interface']['listen_port']}",
            "",
            "👥 Peers:",
        ]
        for p in parsed["peers"]:
            text.append(
                f"— <code>{html.escape(p['public_key'])}</code>\n"
                f"   ➤ Endpoint: {html.escape(p['endpoint'])}\n"
                f"   ➤ IPs: {html.escape(p['allowed_ips'])}\n"
                f"   ➤ Last handshake: {p['latest_handshake']}\n"
                f"   ➤ Traffic: ⬇️ {p['transfer_rx']} | ⬆️ {p['transfer_tx']}"
            )

        await message.answer("\n".join(text), parse_mode="HTML")
    except Exception as e:
        infoLog.error(f"Status failed: {e}")
        await message.answer(f"Error: {e}")


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
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer("Usage: /addclient <name>")
        return
    name = command.args.strip()
    try:
        res = await service.create_client(name)
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
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")


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
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer("Usage: /removeclient <name>")
        return
    name = command.args.strip()
    try:
        await service.delete_client(name)
        await message.answer(f"Client '{name}' removed.")
    except ClientServiceError as e:
        infoLog.error("ClientServiceError: %s", e)
        await message.answer("Ошибка при удалении клиента.")
    except Exception as e:
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")


async def cmd_listclients(message: Message, wg: WGManager, um: UserManager):
    """Обработчик команды /listclients.

    Отправляет пользователю список всех клиентов WireGuard с кнопками
    для просмотра статистики каждого клиента.

    Args:
        message (Message): Сообщение от пользователя.
        wg (WGManager): Менеджер WireGuard.
        um (UserManager): Менеджер пользователей для проверки доступа.
    """
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        clients = wg.list_clients()
        if not clients:
            await message.answer("Нет клиентов.")
            return
        for c in clients:
            text = f"• {c['name']} — {c['ip']} (pubkey: {c['pubkey'][:8]}...)\n"
            kb = InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        InlineKeyboardButton(
                            text="📊 Статистика", callback_data=f"stats:{c['name']}"
                        )
                    ]
                ]
            )
            await message.answer(text, reply_markup=kb)
    except WGManagerError as e:
        await message.answer(f"Failed: {e}")


# --- user management handlers ---
async def cmd_listusers(message: Message, um: UserManager):
    """Обработчик команды /listusers.

    Отправляет администратору список всех пользователей бота с их ролями.

    Args:
        message (Message): Сообщение от пользователя.
        um (UserManager): Менеджер пользователей.
    """
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    users = um.list_users()
    text = "Список пользователей:\n\n"
    for u in users:
        text += f"👤 {u['id']} — {u['role']}\n"
    await message.answer(text)


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
        await message.answer("Usage: /adduser <id> <role>")
        return
    try:
        user_id_str, role = command.args.split(maxsplit=1)
        um.add_user(int(user_id_str), role)
        await message.answer(f"✅ Пользователь {user_id_str} добавлен с ролью {role}.")
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")


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
        await message.answer("Usage: /removeuser <id>")
        return
    try:
        um.remove_user(int(command.args.strip()))
        await message.answer(f"✅ Пользователь {command.args.strip()} удалён.")
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")


async def cmd_syncconfig(message: Message, wg: WGManager, um: UserManager):
    """Обработчик команды /syncconfig.

    Синхронизирует клиентов из всех конфигурационных файлов WireGuard
    в директории, указанной в конфиге (WG_CONFIG_DIR).

    Args:
        message (Message): Сообщение от пользователя.
        wg (WGManager): Менеджер WireGuard.
        um (UserManager): Менеджер пользователей для проверки доступа.
    """
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return

    try:
        result = wg.sync_from_config_dir()
        text = (
            f"✅ Синхронизация завершена:\n\n"
            f"📁 Файлов обработано: {result.get('files_processed', 0)}\n"
            f"📝 Создано: {result['created']}\n"
            f"🔄 Обновлено: {result['updated']}\n"
            f"❌ Ошибок: {len(result['errors'])}"
        )
        if result["errors"]:
            text += "\n\nОшибки:\n" + "\n".join(f"• {e}" for e in result["errors"][:10])
            if len(result["errors"]) > 10:
                text += f"\n... и ещё {len(result['errors']) - 10} ошибок"
        await message.answer(text)
    except WGManagerError as e:
        infoLog.error(f"Sync config error: {e}")
        await message.answer(f"❌ Ошибка синхронизации: {e}")
    except Exception as e:
        infoLog.error(f"Unexpected error during sync: {traceback.format_exc()}")
        await message.answer(f"❌ Неожиданная ошибка: {e}")


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

    setup_logging(args.v)

    try:
        bot_cfg = load_config(args.config)
    except ConfigError as e:
        infoLog.error(f"Config error: {e}")
        sys.exit(1)

    cfg = bot_cfg.as_dict()
    infoLog.info("Config loaded")
    debugLog.debug(
        f"Config details: WG={bot_cfg.wg_interface} DIR={bot_cfg.client_dir} "
        f"SUBNET={bot_cfg.wg_subnet} TOKEN={mask_secret(bot_cfg.telegram_token)}"
    )

    um = UserManager(bot_cfg.users_file, superadmins=bot_cfg.allowed_users)
    wg_admin = WgAdminClient(bot_cfg.wg_admin_socket)
    service = ClientService(bot_cfg, wg_admin)
    wg = WGManager(
        bot_cfg.wg_interface,
        bot_cfg.client_dir,
        bot_cfg.wg_subnet,
        bot_cfg.server_public_key,
        bot_cfg.wg_config_dir,
    )

    bot = Bot(token=bot_cfg.telegram_token)
    dp = Dispatcher()

    dp.message.register(partial(cmd_help, wg=wg, um=um), Command("help"))
    dp.message.register(partial(cmd_status, wg=wg, um=um), Command("status"))
    dp.message.register(partial(cmd_addclient, service=service, um=um), Command("addclient"))
    dp.message.register(
        partial(cmd_removeclient, service=service, um=um), Command("removeclient")
    )
    dp.message.register(partial(cmd_listclients, wg=wg, um=um), Command("listclients"))
    dp.message.register(partial(cmd_syncconfig, wg=wg, um=um), Command("syncconfig"))

    dp.message.register(partial(cmd_listusers, um=um), Command("listusers"))
    dp.message.register(partial(cmd_adduser, um=um), Command("adduser"))
    dp.message.register(partial(cmd_removeuser, um=um), Command("removeuser"))

    dp.callback_query.register(
        partial(cb_stats, wg=wg, um=um), F.data.startswith("stats:")
    )

    await register_bot_commands(bot)
    infoLog.info("Bot starting...")
    try:
        await dp.start_polling(bot)
    finally:
        await wg_admin.close()


if __name__ == "__main__":
    asyncio.run(main())
