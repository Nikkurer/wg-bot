# WireGuard Telegram Bot

Telegram-бот для управления клиентами WireGuard на **RU-сервере** в связке с [wg-install](https://github.com/) (инфраструктура) и [wg-admin](https://github.com/) (API over Unix socket).

Подробное ТЗ: [docs/TZ.md](docs/TZ.md)

## Быстрый старт (локально)

```bash
uv venv && uv sync
cp config.yaml.example config.yaml   # ALLOWED_USERS, SERVER_ENDPOINT
export TELEGRAM_TOKEN=...            # или положить в .env
uv run python main.py -c config.yaml
```

## Деплой на сервер (Docker, рекомендуется)

```bash
# На RU-сервере после wg-install + adduserwg-admin
sudo mkdir -p /var/lib/wg/clients /var/lib/wg/bot /etc/wg-bot
sudo cp config.yaml.example /etc/wg-bot/config.yaml   # логика бота
cp env.example .env                 # TELEGRAM_TOKEN, WG_ADMIN_GID, HOST_* paths
# в .env на сервере: HOST_BOT_STATE_DIR=/var/lib/wg/bot, HOST_CONFIG_DIR=/etc/wg-bot

docker compose up -d --build
```

Пошаговая инструкция: [docs/DEPLOY.md](docs/DEPLOY.md)

## Структура


| Модуль               | Назначение                         |
| -------------------- | ---------------------------------- |
| `main.py`            | Telegram (aiogram), handlers       |
| `config.py`          | Загрузка конфигурации              |
| `wg_admin_client.py` | HTTP-клиент wg-admin (Unix socket) |
| `client_manager.py`  | Keygen, IP, client `.conf`, файлы  |
| `service.py`         | Orchestration create/delete/rotate |
| `users.py`           | RBAC операторов                    |


## Пользователи и роли

Доступ к боту разграничен по ролям (`users.py`).

| Роль         | Как назначается                                  | Права                                              |
| ------------ | ------------------------------------------------ | -------------------------------------------------- |
| `superadmin` | `ALLOWED_USERS` в `config.yaml` (список TG ID)   | Всё; нельзя удалить через бота                      |
| `admin`      | `/adduser <id> admin`                            | Управление клиентами и пользователями              |
| `user`       | `/adduser <id> user`                             | Просмотр: `/status`, `/listclients`, статистика    |

Команды по правам:

- **Любой зарегистрированный** (`user`+): `/help`, `/status`, `/listclients`, кнопка статистики клиента.
- **Только `admin`/`superadmin`**: `/addclient`, `/removeclient`, `/rotateclient`, `/drift`, `/adduser`, `/removeuser`, `/listusers`.

Управление операторами:

```
/adduser 123456789 admin     # выдать права администратора
/adduser 987654321 user      # базовый доступ (просмотр)
/removeuser 987654321        # удалить (superadmin удалить нельзя)
/listusers                   # список операторов с ролями
```

Обычные операторы хранятся в JSON (`USERS_FILE` в state-каталоге), супер-админы — в `config.yaml`.

## Тесты

```bash
uv run pytest tests/ -v
```

