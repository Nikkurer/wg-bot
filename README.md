WireGuard Telegram Bot
======================

Telegram-бот для управления клиентами WireGuard на **RU-сервере** в связке с [wg-install](https://github.com/) (инфраструктура) и [wg-admin](https://github.com/) (API over Unix socket).

Подробное ТЗ: [docs/TZ.md](docs/TZ.md)

Быстрый старт (локально)
------------------------

```bash
uv venv && uv sync
cp config.yaml.example config.yaml   # ALLOWED_USERS, SERVER_ENDPOINT
export TELEGRAM_TOKEN=...            # или положить в .env
uv run python main.py -c config.yaml
```

Деплой на сервер (Docker, рекомендуется)
----------------------------------------

```bash
# На RU-сервере после wg-install + wg-admin
sudo mkdir -p /var/lib/wg/clients /var/lib/wg/bot /etc/wg-bot
sudo cp config.yaml.example /etc/wg-bot/config.yaml   # логика бота
cp env.example .env                 # TELEGRAM_TOKEN, WG_ADMIN_GID, HOST_* paths
# в .env на сервере: HOST_BOT_STATE_DIR=/var/lib/wg/bot, CONFIG_PATH=/etc/wg-bot/config.yaml

docker compose up -d --build
```

Пошаговая инструкция: [docs/DEPLOY.md](docs/DEPLOY.md)

Структура
---------

| Модуль | Назначение |
|--------|------------|
| `main.py` | Telegram (aiogram), handlers |
| `config.py` | Загрузка конфигурации |
| `wg_admin_client.py` | HTTP-клиент wg-admin (Unix socket) |
| `client_manager.py` | Keygen, IP, client `.conf`, файлы |
| `service.py` | Orchestration create/delete/rotate |
| `users.py` | RBAC операторов |

Тесты
-----

```bash
uv run pytest tests/ -v
```
