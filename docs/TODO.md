# Security TODO

Найдено при ревью кодовой базы (2026-06). Приоритет: сверху — срочнее.

Статус: `[ ]` — не сделано, `[~]` — в работе, `[x]` — сделано.

---

## Высокий приоритет

### 1. TOCTOU: index-based callbacks для delete/rotate

**Файлы:** `keyboards.py`, `main.py` (`cb_rotate`, `cb_remove`, `prompt_rotate`, `prompt_remove`)

**Проблема:** в `callback_data` передавался индекс в отсортированном списке. Между «спросить» и «подтвердить» список мог измениться — под тем же индексом оказывался другой клиент.

**Fix:** pubkey в callback (`stats:{pubkey}`, `remove:confirm:{pubkey}` и т.д.); lookup через `client_by_pubkey()`; `build_callback_data()` для проверки 64 байт.

**Статус:** `[x]` — сделано

---

### 2. Path traversal через имена клиентов

**Fix:** validate_name + realpath + display_name/storage_name + orphan delete по pubkey.

**Статус:** `[x]` — сделано (коммиты A/B/C/D)

---

### 3. Доверие к `conf_path` из JSON-метаданных

**Статус:** `[x]` — сделано в коммите A (`_conf_path(name)` вместо meta)

---

### 4. Любой `admin` управляет операторами наравне с superadmin

**Файлы:** `users.py`, `main.py` (`do_add_user`, `cb_useradd`, `cb_userremove`)

**Проблема:** любой `admin` может добавить другого `admin` или удалить коллег (superadmin из `ALLOWED_USERS` только защищён от удаления).

**Fix:** назначение/снятие роли `admin` — только `superadmin`; обычный admin добавляет только `user`.

**Статус:** `[ ]`

---

### 5. `users.json` — слабая защита at rest

**Файлы:** `users.py`, volume `/app/state`

**Проблема:** JSON без schema validation при load; файл пишется без `0o600`; права volume зависят от хоста.

**Fix:** валидация записей (`id: int`, `role ∈ {admin, user}`); запись `0o600`; документировать `chown 1000:1000`, `chmod 750` на state dir.

**Статус:** `[ ]`

---

## Средний приоритет

### 6. Утечка внутренних ошибок в Telegram

**Файлы:** `main.py` — `str(e)` / `f"Ошибка: {e}"` в ответах пользователю

**Fix:** пользователю generic message; детали только в server log.

**Статус:** `[ ]`

---

### 7. Бот не ограничен private chat

**Файлы:** `main.py` — все handlers

**Проблема:** в группе авторизованный оператор может вывести список клиентов, `.conf`, QR — видят все участники.

**Fix:** фильтр `chat.type == "private"`; заметка в README/DEPLOY.

**Статус:** `[ ]`

---

### 8. Private keys WireGuard в Telegram-чате

**Файлы:** `main.py` (`send_client_conf_and_qr`, rotate)

**Проблема:** по дизайну private key уходит документом/QR. Компрометация Telegram = компрометация ключей.

**Fix (смягчение):** документировать риск; опционально ограничить create/rotate superadmin.

**Статус:** `[ ]`

---

### 9. wg-admin Unix socket = полный контроль VPN

**Файлы:** `docker-compose.yml`, `wg_admin_client.py`

**Проблема:** компрометация контейнера → add/remove/rotate peer через socket.

**Fix (defense in depth):** минимальный образ, мониторинг peer changes, ограничение wg-admin по UID.

**Статус:** `[ ]`

---

### 10. `TELEGRAM_TOKEN` может быть в `config.yaml`

**Файлы:** `config.py`

**Fix:** в Docker/production требовать token только из env.

**Статус:** `[ ]`

---

## Низкий приоритет

### 11. Нет audit log RBAC и деструктивных действий

**Fix:** структурированный лог `{actor_id, action, target, timestamp}`.

**Статус:** `[ ]`

---

### 12. `/adduser` без подтверждения

**Fix:** confirm-клавиатура или superadmin-only для slash-пути.

**Статус:** `[ ]`

---

### 13. Debug-логи и права на log file

**Fix:** `DEBUG=0` в prod; log file `0600`.

**Статус:** `[ ]`

---

## Уже хорошо (не трогать без причины)

- `validate_name` + `NAME_PATTERN` при создании клиента
- `_atomic_write` с `0o600` и отказом перезаписывать symlink
- `subprocess` без shell
- `is_user` / `is_admin` на handlers
- `request_id` при user picker
- non-root `USER wgbot` в Dockerfile
- superadmin из config нельзя удалить через бота
