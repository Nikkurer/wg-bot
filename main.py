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
import yaml
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

from users import UserManager
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
            0 - WARNING и выше
            1 - INFO и выше
            2+ - DEBUG и выше
    """
    root = logging.getLogger()
    root.setLevel(
        logging.DEBUG
        if verbosity >= 2
        else (logging.INFO if verbosity == 1 else logging.WARNING)
    )
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    ch_info = logging.StreamHandler(sys.stdout)
    ch_info.setLevel(logging.INFO)
    ch_info.setFormatter(formatter)
    root.addHandler(ch_info)

    fh = logging.FileHandler("wg_bot_debug.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    root.addHandler(fh)

    infoLog.propagate = True
    debugLog.propagate = True


# --- Config loader ---
REQUIRED_KEYS = ["WG_INTERFACE", "CLIENT_DIR", "WG_SUBNET", "TELEGRAM_TOKEN"]


def LoadConfig(path):
    """Загружает конфигурацию из YAML файла.

    Args:
        path (str): Путь к файлу конфигурации.

    Returns:
        dict: Словарь с конфигурацией, содержащий обязательные ключи:
            - WG_INTERFACE: Имя интерфейса WireGuard
            - CLIENT_DIR: Директория для клиентских конфигов
            - WG_SUBNET: Подсеть WireGuard
            - TELEGRAM_TOKEN: Токен Telegram бота
            - ALLOWED_USERS: Список ID супер-администраторов

    Raises:
        FileNotFoundError: Если файл конфигурации не найден или CLIENT_DIR
            не существует.
        KeyError: Если отсутствует обязательный ключ конфигурации.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    for k in REQUIRED_KEYS:
        if k not in cfg:
            raise KeyError(f"Missing required config key: {k}")
    if not os.path.isdir(cfg["CLIENT_DIR"]):
        raise FileNotFoundError(f"CLIENT_DIR not found: {cfg['CLIENT_DIR']}")
    return cfg


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
    message: Message, command: CommandObject, wg: WGManager, um: UserManager
):
    """Обработчик команды /addclient.

    Создаёт нового клиента WireGuard и отправляет конфигурационный файл
    и QR-код пользователю.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументами.
        wg (WGManager): Менеджер WireGuard.
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
        res = wg.add_client(name)
        await message.answer_document(
            document=FSInputFile(res["conf_path"], filename=f"{name}.conf"),
            caption=f"Client '{name}' created with IP {res['client_ip']}",
        )
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
        qr.add_data(res["client_conf"])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        bio = io.BytesIO()
        img.save(bio, "PNG")
        bio.seek(0)
        photo_file = BufferedInputFile(bio.getvalue(), filename=f"{name}.png")
        await message.answer_photo(photo=photo_file, caption=f"QR для клиента '{name}'")
    except WGManagerError as e:
        infoLog.error("WGManagerError: %s", getattr(e, "_full_stderr", str(e)))
        await message.answer("Ошибка при добавлении клиента.")
    except Exception as e:
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")


async def cmd_removeclient(
    message: Message, command: CommandObject, wg: WGManager, um: UserManager
):
    """Обработчик команды /removeclient.

    Удаляет клиента WireGuard по имени.

    Args:
        message (Message): Сообщение от пользователя.
        command (CommandObject): Объект команды с аргументами.
        wg (WGManager): Менеджер WireGuard.
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
        wg.remove_client(name)
        await message.answer(f"Client '{name}' removed.")
    except WGManagerError as e:
        infoLog.error("WGManagerError: %s", getattr(e, "_full_stderr", str(e)))
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
        cfg = LoadConfig(args.config)
    except Exception as e:
        infoLog.error(f"Config error: {e}")
        sys.exit(1)

    infoLog.info(
        f"Config loaded. WG={cfg['WG_INTERFACE']} DIR={cfg['CLIENT_DIR']} SUBNET={cfg['WG_SUBNET']} TOKEN={mask_secret(cfg['TELEGRAM_TOKEN'])}"
    )

    um = UserManager(
        "users.json", superadmins=[int(uid) for uid in cfg["ALLOWED_USERS"]]
    )
    wg = WGManager(
        cfg["WG_INTERFACE"],
        cfg["CLIENT_DIR"],
        cfg["WG_SUBNET"],
        cfg.get("SERVER_PUBLIC_KEY"),
    )

    bot = Bot(token=cfg["TELEGRAM_TOKEN"])
    dp = Dispatcher()

    dp.message.register(partial(cmd_help, wg=wg, um=um), Command("help"))
    dp.message.register(partial(cmd_status, wg=wg, um=um), Command("status"))
    dp.message.register(partial(cmd_addclient, wg=wg, um=um), Command("addclient"))
    dp.message.register(
        partial(cmd_removeclient, wg=wg, um=um), Command("removeclient")
    )
    dp.message.register(partial(cmd_listclients, wg=wg, um=um), Command("listclients"))

    dp.message.register(partial(cmd_listusers, um=um), Command("listusers"))
    dp.message.register(partial(cmd_adduser, um=um), Command("adduser"))
    dp.message.register(partial(cmd_removeuser, um=um), Command("removeuser"))

    dp.callback_query.register(
        partial(cb_stats, wg=wg, um=um), F.data.startswith("stats:")
    )

    await register_bot_commands(bot)
    infoLog.info("Bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
