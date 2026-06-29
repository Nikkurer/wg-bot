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

## Безопасность

- Бот принимает команды **только в личном чате** с оператором. Не добавляйте его в группы — иначе `.conf`, QR и списки клиентов могут увидеть все участники.
- В BotFather для production рекомендуется **Group Privacy** (бот не читает сообщения в группах).
- При создании и ротации клиента бот отправляет **полный `.conf` и QR** с `PrivateKey` в Telegram. Это необходимо для подключения WireGuard, но означает:
  - компрометация аккаунта оператора в Telegram даёт доступ ко всем выданным ключам в истории чата;
  - не пересылайте `.conf` и QR посторонним;
  - после импорта конфига в приложение WireGuard удалите сообщения с файлом и QR из чата с ботом;
  - включите **двухфакторную аутентификацию** в Telegram у всех операторов.
- На диске сервера ключи лежат только в `CLIENT_DIR` (`*.conf`, mode `0600`); в логах бота private key не пишутся.

Подробнее для production: [docs/DEPLOY.md](docs/DEPLOY.md) (раздел про клиентские ключи).

## Структура


| Модуль               | Назначение                         |
| -------------------- | ---------------------------------- |
| `main.py`            | Telegram (aiogram), handlers       |
| `keyboards.py`       | Reply-меню и inline-кнопки         |
| `client_list.py`     | Пагинация и lookup клиентов по pubkey |
| `states.py`          | FSM-состояния диалогов             |
| `config.py`          | Загрузка конфигурации              |
| `wg_admin_client.py` | HTTP-клиент wg-admin (Unix socket) |
| `client_manager.py`  | Keygen, IP, client `.conf`, файлы  |
| `service.py`         | Orchestration create/delete/rotate |
| `users.py`           | RBAC операторов                    |


## Интерфейс (кнопки)

После `/start` бот показывает reply-меню. Основные действия — через кнопки, slash-команды остаются как fallback.

**Все операторы (`user`+):**

| Кнопка | Действие |
| ------ | -------- |
| 📊 Статус | Состояние WireGuard и пиров |
| 👥 Клиенты | Список клиентов (по 8 на страницу) + статистика на карточке |
| ❓ Справка | Справка по меню |

**Только `admin` / `superadmin`:**

| Кнопка | Действие |
| ------ | -------- |
| ➕ Клиент | Диалог: ввод имени → `.conf` + QR |
| ⚠️ Drift | Проверка расхождения storage vs WireGuard |
| 👤 Операторы | Список операторов, добавление и удаление |

На карточке клиента (admin): **🔄 Ротация**, **🗑 Удалить** (с подтверждением).

## Пользователи и роли

Доступ к боту разграничен по ролям (`users.py`).

| Роль         | Как назначается                                  | Права                                              |
| ------------ | ------------------------------------------------ | -------------------------------------------------- |
| `superadmin` | `ALLOWED_USERS` в `config.yaml` (список TG ID)   | Всё; нельзя удалить через бота                      |
| `admin`      | Только `superadmin` (`ALLOWED_USERS`)            | Управление клиентами; добавление/удаление операторов с ролью `user` |
| `user`       | `superadmin` или `admin`                         | Просмотр: статус, список клиентов, статистика      |

Обычные операторы хранятся в JSON (`USERS_FILE` в state-каталоге), супер-админы — в `config.yaml`.

Slash-команды (fallback): `/addclient`, `/removeclient`, `/rotateclient`, `/adduser`, `/removeuser`.

## Тесты

```bash
uv run pytest tests/ -v
```
