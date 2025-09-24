import argparse
import logging
import sys
import yaml
import traceback
import io
import asyncio
import qrcode
import os

from functools import partial
from aiogram import Bot, Dispatcher, F
from aiogram.types import (
    Message, BotCommand, InlineKeyboardMarkup,
    InlineKeyboardButton, CallbackQuery
)
from aiogram.filters import Command, CommandObject

from wg_manager import WGManager, WGManagerError
from users import UserManager, UserManagerError

# --- Logging setup ---
infoLog = logging.getLogger("wg_bot_info")
debugLog = logging.getLogger("wg_bot_debug")

def setup_logging(verbosity):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbosity >= 2 else (logging.INFO if verbosity == 1 else logging.WARNING))
    formatter = logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")

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
    if not s:
        return "<empty>"
    if len(s) <= keep * 2:
        return "<REDACTED>"
    return s[:keep] + "..." + s[-keep:]


async def register_bot_commands(bot: Bot):
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
    if not um.is_user(message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        st = wg.status()
        await message.answer(f"Status:\n<pre>{st}</pre>", parse_mode="HTML")
    except Exception as e:
        infoLog.error(f"Status failed: {e}")
        await message.answer(f"Error: {e}")


async def cmd_addclient(message: Message, command: CommandObject, wg: WGManager, um: UserManager):
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
            document=open(res["conf_path"], "rb"),
            filename=f"{name}.conf",
            caption=f"Client '{name}' created with IP {res['client_ip']}"
        )
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
        qr.add_data(res["client_conf"])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        bio = io.BytesIO()
        bio.name = f"{name}.png"
        img.save(bio, "PNG")
        bio.seek(0)
        await message.answer_photo(photo=bio, caption=f"QR для клиента '{name}'")
    except WGManagerError as e:
        infoLog.error("WGManagerError: %s", getattr(e, "_full_stderr", str(e)))
        await message.answer("Ошибка при добавлении клиента.")
    except Exception as e:
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")


async def cmd_removeclient(message: Message, command: CommandObject, wg: WGManager, um: UserManager):
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
                    [InlineKeyboardButton(text="📊 Статистика", callback_data=f"stats:{c['name']}")]
                ]
            )
            await message.answer(text, reply_markup=kb)
    except WGManagerError as e:
        await message.answer(f"Failed: {e}")


# --- user management handlers ---
async def cmd_listusers(message: Message, um: UserManager):
    if not um.is_admin(message.from_user.id):
        await message.answer("Access denied.")
        return
    users = um.list_users()
    text = "Список пользователей:\n\n"
    for u in users:
        text += f"👤 {u['id']} — {u['role']}\n"
    await message.answer(text)


async def cmd_adduser(message: Message, command: CommandObject, um: UserManager):
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

    infoLog.info(f"Config loaded. WG={cfg['WG_INTERFACE']} DIR={cfg['CLIENT_DIR']} SUBNET={cfg['WG_SUBNET']} TOKEN={mask_secret(cfg['TELEGRAM_TOKEN'])}")

    um = UserManager("users.json", superadmins=[int(uid) for uid in cfg["ALLOWED_USERS"]])
    wg = WGManager(cfg["WG_INTERFACE"], cfg["CLIENT_DIR"], cfg["WG_SUBNET"], cfg.get("SERVER_PUBLIC_KEY"))

    bot = Bot(token=cfg["TELEGRAM_TOKEN"])
    dp = Dispatcher()

    dp.message.register(partial(cmd_help, wg=wg, um=um), Command("help"))
    dp.message.register(partial(cmd_status, wg=wg, um=um), Command("status"))
    dp.message.register(partial(cmd_addclient, wg=wg, um=um), Command("addclient"))
    dp.message.register(partial(cmd_removeclient, wg=wg, um=um), Command("removeclient"))
    dp.message.register(partial(cmd_listclients, wg=wg, um=um), Command("listclients"))

    dp.message.register(partial(cmd_listusers, um=um), Command("listusers"))
    dp.message.register(partial(cmd_adduser, um=um), Command("adduser"))
    dp.message.register(partial(cmd_removeuser, um=um), Command("removeuser"))

    dp.callback_query.register(partial(cb_stats, wg=wg, um=um), F.data.startswith("stats:"))

    await register_bot_commands(bot)
    infoLog.info("Bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
