# main.py
import argparse
import logging
import os
import sys
import yaml
import traceback
import io
import asyncio
import qrcode
from aiogram.types import BotCommand
from aiogram import Bot, Dispatcher
from aiogram.types import Message
from aiogram.filters import Command, CommandObject

from wg_manager import WGManager, WGManagerError

# --- Logging setup ---
infoLog = logging.getLogger("wg_bot_info")
debugLog = logging.getLogger("wg_bot_debug")

def setup_logging(verbosity):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbosity >= 2 else (logging.INFO if verbosity == 1 else logging.WARNING))
    formatter = logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

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
REQUIRED_KEYS = ["WG_INTERFACE", "CLIENT_DIR", "WG_SUBNET", "TELEGRAM_TOKEN", "ALLOWED_USERS"]

def LoadConfig(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    for k in REQUIRED_KEYS:
        if k not in cfg:
            raise KeyError(f"Missing required config key: {k}")
    if not isinstance(cfg["ALLOWED_USERS"], list):
        raise KeyError("ALLOWED_USERS must be a list")
    cfg["ALLOWED_USERS"] = [int(x) for x in cfg["ALLOWED_USERS"]]
    if not os.path.isdir(cfg["CLIENT_DIR"]):
        raise FileNotFoundError(f"CLIENT_DIR not found: {cfg['CLIENT_DIR']}")
    return cfg

# --- helpers ---
def mask_secret(s, keep=4):
    if not s:
        return "<empty>"
    if len(s) <= keep*2:
        return "<REDACTED>"
    return s[:keep] + "..." + s[-keep:]

def user_allowed(cfg, user_id):
    return user_id in cfg["ALLOWED_USERS"]

async def register_bot_commands(bot):
    commands = [
        BotCommand(command="status", description="Показать статус WireGuard"),
        BotCommand(command="addclient", description="Добавить нового клиента"),
        BotCommand(command="removeclient", description="Удалить клиента"),
        BotCommand(command="help", description="Справка по командам"),
    ]
    await bot.set_my_commands(commands)

# --- Handlers ---
async def cmd_help(message: Message, cfg, wg: WGManager):
    if not user_allowed(cfg, message.from_user.id):
        infoLog.info(f"Denied access for user {message.from_user.id}")
        await message.answer("Access denied.")
        return
    await message.answer(
        "WireGuard management bot — команды:\n\n"
        "/status — показать статус (sanitized)\n"
        "/addclient <name> — создать клиента\n"
        "/removeclient <name> — удалить клиента\n"
        "/help — показать это сообщение\n"
    )

async def cmd_status(message: Message, cfg, wg: WGManager):
    if not user_allowed(cfg, message.from_user.id):
        await message.answer("Access denied.")
        return
    try:
        st = wg.status()
        await message.answer(f"Status:\n<pre>{st}</pre>", parse_mode="HTML")
        infoLog.info(f"/status by {message.from_user.id}")
    except Exception as e:
        infoLog.error(f"Status failed: {e}")
        await message.answer(f"Error: {e}")

async def cmd_addclient(message: Message, command: CommandObject, cfg, wg: WGManager):
    if not user_allowed(cfg, message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer("Usage: /addclient <name>")
        return
    name = command.args.strip()
    try:
        res = wg.add_client(name)
        infoLog.info(f"Added client '{name}' by {message.from_user.id}")

        # 1. Отправляем .conf как файл
        await message.answer_document(
            document=open(res["conf_path"], "rb"),
            filename=f"{name}.conf",
            caption=f"Client '{name}' created with IP {res['client_ip']}"
        )

        # 2. Генерируем QR-код из текста конфига
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
        qr.add_data(res["client_conf"])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        bio = io.BytesIO()
        bio.name = f"{name}.png"
        img.save(bio, "PNG")
        bio.seek(0)

        # 3. Отправляем QR-код как фото
        await message.answer_photo(photo=bio, caption=f"QR для клиента '{name}'")

    except WGManagerError as e:
        infoLog.error("WGManagerError: %s", getattr(e, "_full_stderr", str(e)))  # подробности только в лог
        await message.answer("Операция не выполнена (внутренняя ошибка). Администратор уведомлен.")
    except Exception as e:
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")

async def cmd_removeclient(message: Message, command: CommandObject, cfg, wg: WGManager):
    if not user_allowed(cfg, message.from_user.id):
        await message.answer("Access denied.")
        return
    if not command.args:
        await message.answer("Usage: /removeclient <name>")
        return
    name = command.args.strip()
    try:
        wg.remove_client(name)
        infoLog.info(f"Removed client '{name}' by {message.from_user.id}")
        await message.answer(f"Client '{name}' removed.")
    except WGManagerError as e:
        infoLog.error("WGManagerError: %s", getattr(e, "_full_stderr", str(e)))  # подробности только в лог
        await message.answer("Операция не выполнена (внутренняя ошибка). Администратор уведомлен.")
    except Exception as e:
        infoLog.error(f"Unexpected error: {traceback.format_exc()}")
        await message.answer(f"Unexpected error: {e}")

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

    wg = WGManager(cfg["WG_INTERFACE"], cfg["CLIENT_DIR"], cfg["WG_SUBNET"], cfg.get("SERVER_PUBLIC_KEY"))
    bot = Bot(token=cfg["TELEGRAM_TOKEN"])
    dp = Dispatcher()

    dp.message.register(lambda m: cmd_help(m, cfg, wg), Command("help"))
    dp.message.register(lambda m: cmd_status(m, cfg, wg), Command("status"))
    dp.message.register(lambda m, c: cmd_addclient(m, c, cfg, wg), Command("addclient"))
    dp.message.register(lambda m, c: cmd_removeclient(m, c, cfg, wg), Command("removeclient"))

    # 👇 Регистрируем команды в Telegram API
    await register_bot_commands(bot)

    infoLog.info("Bot starting...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
