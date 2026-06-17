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
# Отредактируйте ALLOWED_USERS, SERVER_ENDPOINT

cp env.example .env
# Обязательно: TELEGRAM_TOKEN, WG_ADMIN_GID
# На сервере: HOST_BOT_STATE_DIR=/var/lib/wg/bot, HOST_CONFIG_DIR=/etc/wg-bot
```

### Что где задаётся

| Параметр | Файл | Назначение |
|----------|------|------------|
| `TELEGRAM_TOKEN` | `.env` | Секрет бота |
| `WG_ADMIN_GID` | `.env` | Доступ к Unix-сокету wg-admin |
| `HOST_*` | `.env` | Пути **на хосте** для docker volume mounts (`HOST_CONFIG_DIR` — каталог с `config.yaml`) |
| Подсети, `SERVER_ENDPOINT`, RBAC | `config.yaml` | Логика VPN и бота **внутри контейнера** |
| `CLIENT_DIR`, `USERS_FILE`, `WG_ADMIN_SOCKET` | defaults в коде | Пути внутри контейнера (менять только при кастомных mount) |
| Имя интерфейса, `SERVER_PUBLIC_KEY` | wg-admin при старте | Автоподстановка из `/interface/status` |

`TELEGRAM_TOKEN` в `config.yaml` **не нужен** — только в `.env`.

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
export HOST_CONFIG_DIR=/etc/wg-bot
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

### `Temporary failure resolving 'deb.debian.org'` при `docker compose build`

Сборка образа не может резолвить DNS (часто на VPS с кривой bridge-сетью Docker).

1. В `docker-compose.yml` уже включено `build.network: host` — обновите репо и пересоберите:

```bash
git pull
docker compose build --no-cache
```

2. Проверка DNS с хоста и из контейнера:

```bash
getent hosts deb.debian.org
docker run --rm alpine nslookup deb.debian.org
docker run --rm --network host alpine nslookup deb.debian.org
```

3. Если с хоста резолвится, а без `--network host` — нет, задайте DNS для Docker (`/etc/docker/daemon.json`):

```json
{
  "dns": ["1.1.1.1", "8.8.8.8"]
}
```

```bash
sudo systemctl restart docker
```

### `Is a directory: '/config/config.yaml'`

Файл `config.yaml` на хосте не существовал при первом `docker compose up` — Docker создал **каталог** вместо файла.

```bash
docker compose down
# локально в /opt/wg-bot, если config.yaml — каталог:
rm -rf config.yaml
cp config.yaml.example config.yaml

# на сервере:
sudo rm -rf /etc/wg-bot/config.yaml   # только если это каталог, не файл!
sudo cp config.yaml.example /etc/wg-bot/config.yaml
# .env: HOST_CONFIG_DIR=/etc/wg-bot  (каталог, не путь к файлу)

docker compose up -d --build
```

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
