# Status — проектирование

**Статус:** draft, без реализации (2026-06)  
**Контекст:** команда `/status` (кнопка «📊 Статус») сейчас выводит **полный список peer'ов** с endpoint, IP, handshake и трафиком — по сути дублирует «Клиенты» + stats. После client ownership это ещё и раскрывает чужих клиентов пользователям с ролью `user`.

---

## Цель

Показывать **ключевое состояние сервиса**, а не каталог клиентов. Детали по каждому peer — через «👥 Клиенты» → «📊 Статистика» на карточке.

---

## Текущее поведение

`/status` → `GET /interface/status` (wg-admin, интерфейс `wg-ru-clients`):

- имя интерфейса, `state` (UP/DOWN)
- **все** peer'ы: description, pubkey, endpoint, allowed_ips, handshake, rx/tx

Одинаковый вывод для `user`, `admin`, `superadmin`.

**Проблемы:**

1. Дублирование «Клиенты» / stats.
2. Утечка информации: `user` видит чужие имена и IP (противоречит client ownership).
3. Длинное сообщение при большом числе клиентов.
4. Нет агрегированной сводки (сколько online, drift и т.д.).

---

## Принятые решения

| # | Вопрос | Решение |
|---|--------|---------|
| 1 | Формат индикаторов | 🟢 — работает (без лишнего текста). 🟡 / 🔴 — деградация или сбой **с пояснением** |
| 2 | Сводка по клиентам | **Admin:** всего + online по всем peer'ам. **User:** только счётчик **своих** (`owner == actor`): «N всего · M online», **без списка** |
| 3 | Drift | Показывать admin/superadmin **одной строкой** в status при расхождении |
| 4 | EU tunnel (`wg-ru-eu`) | **Не в v1** — добавим позже (отдельный блок в документе) |
| 5 | Ошибки wg-admin | **User:** «VPN-сервер: недоступен» (без технических деталей). **Admin:** текст ошибки для диагностики |
| 6 | Endpoint | **User и admin:** `host:port` из config (`SERVER_ENDPOINT` / `client_endpoint()`) — адрес подключения клиентов |

---

## Целевой UX (v1)

### User

```text
📊 Статус VPN

🟢 VPN-сервер
📡 Endpoint: vpn.example.com:443

👤 Клиенты: 2 всего / 1 online
```

- Блок **VPN-сервер** — только emoji + короткий статус; имя интерфейса, pubkey **не показываем**.
- **Endpoint** — `cfg.client_endpoint()` (тот же, что в client `.conf`); полезен user'у при проверке доступности сервера от себя.
- Блок **Клиенты** — **только** счётчик «всего / online» по peer'ам с `owner == actor_id` и `has_local_conf`. Имена, handshake, список — **не показываем** (детали в «Клиенты»).

При ошибке API:

```text
📊 Статус VPN

🔴 VPN-сервер — сервис временно недоступен
```

### Admin / superadmin

```text
📊 Статус VPN

🟢 Entry: wg-ru-clients — UP
👥 Клиенты: 12 всего / 8 online
📡 Endpoint: vpn.example.com:443
✅ Storage: in sync
```

При drift:

```text
⚠️ Storage: drift detected (3 расхождения) — /drift для деталей
```

При сбое:

```text
🔴 Entry: недоступен — Failed to connect to wg-admin: ...
```

---

## Индикаторы состояния

### VPN-сервер (entry, `wg-ru-clients`)

| Состояние | Иконка | Условие | Текст (пример) |
|-----------|--------|---------|----------------|
| OK | 🟢 | `state == UP`, wg-admin ответил | *(без доп. текста у user)* / `wg-ru-clients — UP` у admin |
| Down | 🔴 | `state != UP` или исключение при запросе | «интерфейс DOWN» / «сервис временно недоступен» |

### Клиент «online» (для summary)

Peer считается **online**, если `latest_handshake` не старше порога (предложение: **3 мин**).

| Состояние | Иконка | Условие | Текст (пример) |
|-----------|--------|---------|----------------|
| Online | 🟢 | handshake ≤ `ONLINE_THRESHOLD` | `handshake 1m ago` |
| Idle | ⚪ | handshake был, но старше порога | `last seen 2h ago` |
| Never | ⚪ | `latest_handshake == null` | `never connected` |

Пороги вынести в config (см. ниже).

### Drift (только admin)

| Состояние | Иконка | Условие |
|-----------|--------|---------|
| OK | ✅ | `detect_drift().in_sync == true` |
| Warning | ⚠️ | `in_sync == false` — кратко: число расхождений + отсылка к `/drift` |

Drift — **отдельный** вызов `GET /peer/drift` (добавляет latency к `/status`; допустимо для admin).

---

## Сводка по клиентам

### Admin

- **Всего** — число peer'ов в `interface/status.peers` (или merge с local, если нужны orphan — уточнить при реализации).
- **Online** — peer'ы с handshake ≤ `ONLINE_THRESHOLD`.

Orphan и legacy в общий счёт **включать** (admin видит всё).

### User

- Фильтр: `can_view_client(actor, client)` — те же правила, что в «Клиенты» (свои с `owner == actor`, с local conf).
- **Всего / online** — только по отфильтрованному списку; вывод **одной строкой**, без перечисления клиентов.

Legacy и orphan в user summary **не попадают**.

---

## Источники данных (v1)

| Блок | API / код | RBAC |
|------|-----------|------|
| VPN UP/DOWN | `GET /interface/status` → `name`, `state` | user+ |
| Client summary | `interface/status.peers` + merge/filter по ownership | user (свои) / admin (все) |
| Endpoint (сервер) | `BotConfig.client_endpoint()` | user+ |
| Drift | `GET /peer/drift` | admin |

**Убрать из `/status`:** полный дамп peer list с per-peer endpoint, IP, rx/tx (остаётся в «Клиенты» → stats). **Server endpoint** из config — показываем user и admin.

---

## EU tunnel — отложено (v2)

На RU-ноде второй интерфейс `wg-ru-eu` (туннель RU↔EU). Сейчас wg-admin обслуживает только `wg-ru-clients`; бот **не видит** EU.

**Целевой UX (когда появится API):**

| Роль | Показ |
|------|-------|
| user | 🟢/🟡/🔴 «Канал EU» + пояснение при проблеме |
| admin | + имя интерфейса, handshake, rx/tx peer'а на EU |

**Варианты реализации (на выбор позже):**

1. Расширить wg-admin: `GET /interface/status?interface=wg-ru-eu` или `/tunnel/eu/status`.
2. Агрегированный health в одном ответе wg-admin.

Пороги деградации EU (draft): hs > 3 мин → 🟡, hs > 10 мин или DOWN → 🔴.

---

## Config (draft)

```yaml
# Порог «online» для summary (секунды)
STATUS_ONLINE_THRESHOLD_SEC: 180
```

EU-пороги — добавить в v2 вместе с мониторингом туннеля.

---

## Изменения по слоям (когда будем делать)

### Новый модуль (предложение: `status_format.py`)

- `build_status_message(actor_id, um, wg_admin, service, cfg) -> str`
- `vpn_server_indicator(status) -> (icon, label, detail?)`
- `client_summary(clients, *, online_threshold) -> str`
- `drift_indicator(report) -> str` (admin)

### `main.py`

- Переписать `cmd_status`: ветка user vs admin, без цикла по всем peer'ам в «полном» формате.
- User: merge/filter через `filter_clients_for_actor` + handshake из `interface/status` по pubkey.

### `wg_admin_client.py`

- Без изменений в v1 (EU — позже).

### `keyboards.py` / help

- Обновить описание кнопки «📊 Статус» в `/help`.

### Тесты

- `tests/test_status_format.py` — индикаторы, фильтр user summary, drift line, ошибка API (user vs admin).

---

## Матрица: что где смотреть

| Информация | `/status` | `/listclients` | stats на карточке |
|------------|-----------|----------------|-------------------|
| VPN UP/DOWN | ✅ | — | — |
| Endpoint (сервер) | ✅ user+ | — | в `.conf` |
| Drift (admin) | ✅ кратко | — | `/drift` детально |
| Сводка клиентов | ✅ (user: счётчик; admin: счётчик) | список | — |
| Handshake / трафик peer | — | — | ✅ полностью |
| EU tunnel | v2 | — | — |

---

## Безопасность

- User **не** получает чужие имена/IP через `/status`.
- Admin при ошибке может видеть внутренний текст — только в личном чате с ботом (см. TODO #7 private chat).
- Drift не раскрывает лишнего user'у.

---

## Объём работ (оценка)

| PR | Содержание |
|----|------------|
| PR1 | `status_format.py` + user/admin ветки в `cmd_status`, убрать full peer dump |
| PR2 | Drift line для admin, config порогов, тесты |
| PR3 | EU tunnel (после API в wg-admin), README/help |

---

## Связь с другими документами

- [CLIENT-OWNERSHIP.md](./CLIENT-OWNERSHIP.md) — фильтр «своих» клиентов для user summary (`owner`, `can_view_client`).
- [TZ.md](./TZ.md) — архитектура RU/EU, scope бота только на RU entry.
- `/drift` — детальный отчёт drift (без изменений).

---

## Закрытые вопросы

1. Индикаторы: 🟢 без текста при OK, 🟡/🔴 с пояснением → **да**
2. Summary клиентов: admin — все, user — свои, **только счётчик** → **да**
3. Drift в status для admin → **да**
4. EU → **отложено**
5. Ошибки: user generic, admin детально → **да**
6. Endpoint в status для user → **да**

## Остаётся уточнить (перед PR1)

1. **Счётчик admin:** только peer'ы из `interface/status` или merge с orphan из storage?
2. **`ONLINE_THRESHOLD`:** 3 мин достаточно или привязать к `persistent_keepalive` (25s)?
