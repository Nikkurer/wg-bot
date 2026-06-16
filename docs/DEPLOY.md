# Деплой wg-bot на RU-сервер (Docker)

Рекомендуемая схема для production после **wg-install**:

| Компонент | Где работает |
|-----------|--------------|
| WireGuard, BIRD, nftables | хост (wg-install) |
| **wg-admin** | systemd на хосте (root) |
| **wg-bot** | Docker |

```
RU-сервер
├── wg-quick@wg-ru-clients.service
├── wg-admin.service              → /run/wg-admin/wg-admin.sock
└── docker compose (wg-bot)       → volume: socket + /var/lib/wg/clients
```

---

## 1. Предварительные условия

- RU-сервер развёрнут через **wg-install**
- **wg-admin** установлен и запущен (`systemd`), интерфейс `wg-ru-clients`
- Docker Engine + Docker Compose v2 на сервере
- UID процесса wg-bot на хосте wg-admin: `-allowed-uids` должен включать UID `1000` (пользователь `wgbot` в образе)

Проверка wg-admin:

```bash
sudo systemctl status wg-admin
ls -la /run/wg-admin/wg-admin.sock
getent group wg-admin
```

---

## 2. Подготовка каталогов на хосте

```bash
sudo groupadd -f wg-admin

sudo mkdir -p /var/lib/wg/clients /var/lib/wg/bot /etc/wg-bot
sudo chown -R 1000:1000 /var/lib/wg/clients /var/lib/wg/bot
sudo chmod 750 /var/lib/wg/clients /var/lib/wg/bot
```

---

## 3. Конфигурация

```bash
cd /opt/wg-bot   # или клон репозитория

sudo cp config.yaml.example /etc/wg-bot/config.yaml
# Отредактируйте ALLOWED_USERS, SERVER_PUBLIC_KEY, SERVER_ENDPOINT (v2)

cp env.example .env
# Обязательно:
#   TELEGRAM_TOKEN=...
#   WG_ADMIN_GID=$(getent group wg-admin | cut -d: -f3)
```

`TELEGRAM_TOKEN` можно не класть в `config.yaml` — при наличии переменной окружения она имеет приоритет.

---

## 4. wg-admin: доступ для контейнера

wg-admin должен создавать сокет с группой `wg-admin`:

```ini
ExecStart=/usr/local/bin/wg-admin \
  -socket /run/wg-admin/wg-admin.sock \
  -socket-group wg-admin \
  ...
```

Если используется `-allowed-uids`, добавьте UID контейнера:

```bash
# UID 1000 = пользователь wgbot в образе
wg-admin ... -allowed-uids "0,1000"
```

---

## 5. Запуск

```bash
export CONFIG_PATH=/etc/wg-bot/config.yaml
docker compose up -d --build
docker compose logs -f wg-bot
```

Обновление:

```bash
git pull
docker compose up -d --build
```

---

## 6. Volumes

| Host | Container | Назначение |
|------|-----------|------------|
| `/run/wg-admin` | `/run/wg-admin` (ro) | Unix socket wg-admin |
| `/var/lib/wg/clients` | `/var/lib/wg/clients` | Client `.conf`, `.json` |
| `/var/lib/wg/bot` | `/app/state` | `users.json`, `wg_bot_debug.log` |
| `/etc/wg-bot/config.yaml` | `/config/config.yaml` (ro) | Настройки |

---

## 7. Troubleshooting

### `Permission denied` на socket

```bash
# GID в .env должен совпадать с группой сокета
stat -c '%g %G' /run/wg-admin/wg-admin.sock
getent group wg-admin
grep WG_ADMIN_GID .env
```

Пересоздайте контейнер после смены `group_add` (restart недостаточно).

### `403 Forbidden` от wg-admin

UID процесса в контейнере не в `-allowed-uids`. Проверка:

```bash
docker compose exec wg-bot id
```

### Healthcheck failing

wg-admin не запущен или сокет в другом пути — сверьте `WG_ADMIN_SOCKET_DIR` и unit-файл wg-admin.

### Client files not writable

```bash
sudo chown -R 1000:1000 /var/lib/wg/clients /var/lib/wg/bot
```

---

## 8. Альтернатива: systemd без Docker

Для dev или минимального окружения — см. §8.2 в [TZ.md](TZ.md) (пользователь `deploy` в группе `wg-admin`).

Docker предпочтителен для production: изолированные зависимости, простые обновления образа.
