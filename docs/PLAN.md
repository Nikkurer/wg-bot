# План реализации wg-bot v2

**Цель:** перевести бота с прямого `sudo wg` на интеграцию с **wg-admin** + **wg-install** (RU-only).  
**База:** [TZ.md](TZ.md), [DEPLOY.md](DEPLOY.md)  
**Стратегия:** эволюционный рефакторинг, один рабочий коммит после каждого шага.

---

## Уже сделано (этап 0)

- [x] ТЗ v2 (`docs/TZ.md`)
- [x] Docker-деплой (`Dockerfile`, `docker-compose.yml`, `docs/DEPLOY.md`)
- [x] `config.yaml.example` под wg-install RU
- [x] Env overrides в `main.py`: `TELEGRAM_TOKEN`, `USERS_FILE`, `WGBOT_LOG_DIR`

---

## Этап 1. Конфигурация v2

**Цель:** единый загрузчик конфига с валидацией под RU-сервер.

**Задачи:**
1. Расширить `LoadConfig()` / вынести в `config.py`:
   - обязательные: `WG_INTERFACE`, `CLIENT_DIR`, `WG_SUBNET`, `TELEGRAM_TOKEN`, `ALLOWED_USERS`
   - новые обязательные для v2: `WG_ADMIN_SOCKET`, `SERVER_PUBLIC_KEY`, `SERVER_ENDPOINT`
   - опциональные: `WG_SUBNET_V6`, `WG_CLIENT_PORT`, `WG_MTU`, `WG_DNS`, `CLIENT_ALLOWED_IPS`, `PERSISTENT_KEEPALIVE`, `USERS_FILE`
2. Env overrides: `TELEGRAM_TOKEN`, `USERS_FILE`, `WG_ADMIN_SOCKET`
3. Обновить `config.yaml.example`, добавить тесты загрузки конфига

**Проверка:**
```bash
uv run pytest tests/test_config.py -v
```

**Коммит:** «Расширил конфигурацию под интеграцию с wg-admin»

---

## Этап 2. Клиент wg-admin

**Цель:** HTTP over Unix socket к wg-admin API.

**Задачи:**
1. Добавить зависимость `httpx` (async, Unix transport)
2. Создать `wg_admin_client.py`:
   - `WgAdminError` — ошибки API
   - `WgAdminClient` — async методы:
     - `add_peer`, `remove_peer`, `rotate_peer`
     - `list_peers`, `interface_status`, `detect_drift`
   - парсинг JSON `{status, data|message}`
3. Dataclass-модели: `PeerInfo`, `InterfaceStatus`, `DriftReport`
4. Тесты с mock transport (без реального socket)

**Проверка:**
```bash
uv run pytest tests/test_wg_admin_client.py -v
```

**Коммит:** «Добавил клиент wg-admin API»

---

## Этап 3. Client manager (локальная логика бота)

**Цель:** всё, что wg-admin **не** делает — keygen, IP, client conf, файлы.

**Задачи:**
1. Создать `client_manager.py`, перенести из `wg_manager.py`:
   - `_gen_keypair()` — `wg genkey` / `wg pubkey` **без sudo**
   - `_list_used_ips()` / `_next_free_ip()` — IPv4 + IPv6 (общий host-id)
   - `_atomic_write()`, проверка прав `CLIENT_DIR`
   - `build_client_conf()` — полный `.conf` по TZ §6.2
   - `save_client()` / `load_client()` / `remove_client_files()` — `.json` + `.conf`
2. Формат `{name}.json` по TZ §6.3 (`client_ip_v6`, `created_at`)
3. Тесты: keygen (mock subprocess), IP allocation, conf builder, atomic write

**Проверка:**
```bash
uv run pytest tests/test_client_manager.py -v
```

**Коммит:** «Добавил client_manager для keygen, IP и client conf»

---

## Этап 4. Orchestration-слой

**Цель:** связать `ClientManager` + `WgAdminClient` в операции add/remove/rotate.

**Задачи:**
1. Создать `service.py` (или методы в `ClientManager`):
   - `create_client(name)` — keygen → IP → `/peer/add` → save files
   - `delete_client(name)` — load meta → `/peer/remove` → delete files
   - `rotate_client(name)` — keygen → `/peer/rotate` → reissue conf
   - rollback-логика по TZ §4.2, §12.3
2. Тесты с mock wg-admin + temp CLIENT_DIR

**Проверка:**
```bash
uv run pytest tests/test_service.py -v
```

**Коммит:** «Добавил orchestration create/delete/rotate клиентов»

---

## Этап 5. Handlers: add / remove

**Цель:** первые mutating-команды через wg-admin.

**Задачи:**
1. Переписать `cmd_addclient` → `service.create_client()` + QR (без изменений UX)
2. Переписать `cmd_removeclient` → `service.delete_client()`
3. DI в `main.py`: `WgAdminClient` + `ClientManager` вместо `WGManager`
4. Убрать `sudo` из Dockerfile/runtime (keygen без root)

**Проверка (staging RU):**
```bash
/addclient test1          # peer в wg show + .conf + QR
/removeclient test1       # peer удалён
curl --unix-socket ... GET /peer/drift  # in_sync
```

**Коммит:** «Перевёл addclient и removeclient на wg-admin»

---

## Этап 6. Handlers: read-only

**Цель:** status, list, stats без прямого `wg show`.

**Задачи:**
1. `cmd_status` → `GET /interface/status` + форматирование (HTML)
2. `cmd_listclients` → merge `/peer/list` (description=имя) + CLIENT_DIR
3. `cb_stats` → данные из `/interface/status` или `/peer/list` (rx/tx, handshake)
4. Обновить `/help` и `register_bot_commands`

**Проверка:**
```bash
/status
/listclients
# кнопка «Статистика»
```

**Коммит:** «Перевёл status, listclients и stats на wg-admin»

---

## Этап 7. Новые команды: drift и rotate

**Цель:** закрыть оставшиеся требования TZ §6.1, §12.

**Задачи:**
1. `cmd_drift` → `GET /peer/drift`, человекочитаемый отчёт
2. `cmd_rotateclient`:
   - inline-подтверждение (callback `rotate:{name}`)
   - `service.rotate_client()` → новый conf + QR
   - предупреждение «старый conf недействителен»
3. Зарегистрировать команды в меню бота

**Проверка:**
```bash
/drift                    # in_sync: true
/rotateclient test1       # confirm → новый QR, IP тот же
```

**Коммит:** «Добавил команды drift и rotateclient»

---

## Этап 8. Удаление legacy

**Цель:** убрать v1-код.

**Задачи:**
1. Удалить `cmd_syncconfig`, регистрацию `/syncconfig`
2. Удалить `wg_manager.py`
3. Перенести/удалить `tests/test_wg_manager.py` (актуальные тесты уже в новых модулях)
4. Обновить `Dockerfile` (COPY новых модулей)
5. Обновить `README.md`, `pyproject.toml`

**Проверка:**
```bash
uv run pytest tests/ -v
docker build -t wg-bot:test .
```

**Коммит:** «Удалил wg_manager и syncconfig (legacy v1)»

---

## Этап 9. Staging e2e на RU-сервере

**Цель:** полная проверка связки wg-install + wg-admin + wg-bot (Docker).

**Предусловия:**
- wg-install прокатан на RU
- wg-admin systemd: `-interface wg-ru-clients`, `-socket-group wg-admin`, `-allowed-uids 0,1000`
- `/etc/wg-bot/config.yaml` из example
- `.env`: `TELEGRAM_TOKEN`, `WG_ADMIN_GID`

**Чеклист:** TZ §10 (критерии приёмки)

| # | Проверка |
|---|----------|
| 1 | `docker compose up -d` — healthcheck green |
| 2 | `/addclient alice` — handshake с RU, split-маршрутизация |
| 3 | Client conf: DNS `10.66.66.1`, Endpoint `:443`, IPv4+IPv6 |
| 4 | `/listclients`, `/status` |
| 5 | `/rotateclient alice` — reconnect с новым conf |
| 6 | `/removeclient alice` |
| 7 | `/drift` → in_sync |
| 8 | restart wg-admin → peers на месте (reconcile) |
| 9 | RBAC: user не может add/remove |

**Коммит (если нужны правки):** «Исправил … по результатам staging»

---

## Этап 10. CI и финализация

**Задачи:**
1. GitHub Actions: `docker build` (optional smoke)
2. Pin версии образа в compose для production
3. (опционально) Ansible-роль в wg-install: deploy wg-bot compose

**Коммит:** «Добавил сборку Docker-образа в CI»

---

## Зависимости между этапами

```
0 (done) → 1 → 2 ─┐
                   ├→ 4 → 5 → 6 → 7 → 8 → 9 → 10
              3 ───┘
```

Этапы 2 и 3 можно делать **параллельно**.  
Этап 9 — только после 5–8.

---

## Оценка объёма

| Этап | Новый код | Риск |
|------|-----------|------|
| 1 | ~80 строк | низкий |
| 2 | ~200 строк + тесты | средний (Unix socket) |
| 3 | ~250 строк + тесты | низкий (перенос) |
| 4 | ~150 строк + тесты | средний (rollback) |
| 5–7 | правки main.py | средний (Telegram UX) |
| 8 | удаление ~800 строк | низкий |
| 9 | ручное тестирование | высокий (prod-like) |

**Итого:** ~8–10 коммитов, ~3–5 дней focused work.

---

## Вне плана (v2.1+)

- Rename клиента
- Ansible-роль деплоя бота в wg-install
- Push-алерты при drift
- Multi-admin audit log в файл/SIEM
