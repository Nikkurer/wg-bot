# Client ownership — проектирование

**Статус:** реализовано на ветке `feat/client-ownership` (2026-06)
**Контекст:** сейчас роль `user` видит всех клиентов, но не может ими управлять. Роль `admin` управляет **всем** пулом. Нет привязки «клиент → оператор».

---

## Цель

Дать операторам с ролью `user` **ограниченное управление своими клиентами** (создание, ротация, удаление), не открывая доступ к чужим peer'ам и админ-функциям.

---

## Текущая модель RBAC

| Действие | `user` | `admin` | `superadmin` |
|----------|--------|---------|--------------|
| Статус, список, stats | все клиенты | все | все |
| Создать / rotate / delete | ❌ | все | все |
| Drift, операторы | ❌ | ✅ / частично | ✅ |

Ownership **нигде не хранится**: в `{name}.json` есть `name`, `pubkey`, `client_ip`, `created_at`, но нет `owner`.

---

## Варианты модели

### A. Owner только в local meta (рекомендуется для v1)

При `save_client()` записывать в JSON:

```json
{
  "name": "alice",
  "pubkey": "...",
  "owner": 123456789,
  "created_at": "..."
}
```

**Проверка прав:** перед create/rotate/delete — `can_manage_client(actor_id, client)`.

| Роль | Правило |
|------|---------|
| `superadmin` | любой клиент |
| `admin` | любой клиент (или только свои — см. вопросы) |
| `user` | только `owner == actor_id` |

**Плюсы:** минимальные изменения, не зависит от wg-admin.  
**Минусы:** orphan peer (нет local `.json`) — owner неизвестен; старые клиенты без `owner`.

### B. Owner в wg-admin `peer.description`

Кодировать owner в description, например `alice@123456789` или JSON.

**Минусы:** ломает человекочитаемые имена; wg-admin — общий источник правды для orphan; сложнее миграция.

**Не рекомендуется** при текущей архитектуре (description = storage name для local clients).

### C. Отдельный index-файл `owners.json`

`pubkey → operator_id` в state dir.

**Плюсы:** быстрый lookup по pubkey для orphan после первого «claim».  
**Минусы:** второй источник правды, рассинхрон с meta.

---

## Принятые решения

| # | Вопрос | Решение |
|---|--------|---------|
| 1 | Видимость для `user` | **Только свои** клиенты (`owner == actor`) |
| 2 | Видимость для `admin` | **Все** клиенты + **подпись владельца** на карточке |
| 3 | Legacy без `owner` | **Навсегда admin-only** (manage + видны admin/superadmin с меткой «без владельца») |
| 4 | Orphan peer (нет local conf) | **Admin-only** (user не видит; manage как сейчас) |

Дополнительно (по умолчанию для v1, если не оспорено):

- `superadmin` — как `admin` (видит всех + владелец), manage любой клиент
- `admin` manage — **все** клиенты (не только свои)
- `user` manage — create / rotate / delete **только своих**
- `user` получает **➕ Клиент** в reply-меню
- Флаг `ADMIN_MANAGES_ALL` **не нужен** в v1

---

## Рекомендация: A + правила для legacy/orphan

### `can_manage_client(actor, client) -> bool`

```text
superadmin                          → true
admin                               → true (любой клиент с local conf или orphan)
user                                → owner == actor
client without owner (legacy)  → admin/superadmin only
orphan (no local conf)              → admin/superadmin only
```

### `can_view_client(actor, client) -> bool`

```text
superadmin / admin                  → true (все, включая legacy и orphan)
user                                → has_local_conf and owner == actor
```

---

## Отображение владельца (admin / superadmin)

На карточке клиента дополнительная строка, например:

```text
• alice — 10.66.66.2/32 (pubkey: abcd1234...)
  👤 Владелец: Ivan Petrov (@ivan)
```

| `owner` | Подпись |
|--------------|---------|
| известный оператор | имя / @username (как в списке операторов) |
| ID не в `users.json` | `ID 123456789 <deleted>` |
| `null` (legacy) | `без владельца (legacy)` |
| orphan | `—` или не показывать (нет local meta) |

---

## Изменения по слоям

Реализовано в `client_ownership.py`, `client_manager.py`, `service.py`, `main.py`, `keyboards.py`.

### `client_manager.py`

- `save_client(..., owner: int)`
- `load_client` → поле `owner` (optional)
- helper `client_owned_by(record, operator_id)`

### `service.py`

- `create_client(name, *, actor_id)` — прокидывает `owner`
- `list_clients_merged()` — добавляет `owner` в dict (из meta; для orphan `None`)
- `delete_client` / `rotate_client` — проверка через `can_manage_client`

### `main.py`

- Передавать `message.from_user.id` / `callback.from_user.id` во все mutating операции
- Фильтр списка (если выбран strict view)
- `client_actions_keyboard(..., can_manage: bool)` — rotate/remove только если manage
- Для `user`: показать **➕ Клиент** в reply-меню (сейчас только admin)

### `users.py` / config

- Без доп. флагов в v1

### Миграция

| Категория | Поведение |
|-----------|-----------|
| Существующие `.json` без `owner` | admin-only manage; admin видит с меткой «legacy»; user не видит |
| Orphan peer | admin-only; user не видит |

---

## Матрица UX после внедрения (draft)

Предположение: **user видит только своих**, admin — всех.

| Действие | `user` (свой) | `user` (чужой) | `admin` |
|----------|---------------|----------------|---------|
| В списке | ✅ | скрыт | ✅ |
| Stats | ✅ | — | ✅ |
| Create | ✅ | — | ✅ |
| Rotate / delete | ✅ | ❌ | ✅ |
| Orphan delete | ❌ | ❌ | ✅ |

---

## Безопасность

- Проверка **на сервере** при confirm (не только скрытие кнопок)
- `owner` в meta — не доверять для проверки без загрузки meta по `storage_name` (уже есть pubkey lookup)
- Audit log (TODO #11): `{actor, action, client, pubkey}` — особенно важен при shared admin pool

---

## Объём работ (оценка)

| PR | Содержание |
|----|------------|
| PR1 | `owner` в meta + `create_client(actor_id)` + тесты |
| PR2 | `can_manage_client` + guards на rotate/delete + UI кнопки |
| PR3 | ➕ Клиент для `user`, фильтр списка, подпись владельца для admin |
| PR4 | README, help, документация |

---

## Остаётся уточнить (перед PR1)

### A. Кто владелец при создании admin'ом?

**Предложение по умолчанию:** `owner` = Telegram ID того, кто нажал «создать».

- Admin создал → клиент **принадлежит admin'у**, user его **не видит**
- «Создать клиента **для** user X» — отдельная фича, **не в v1**

### B. Лимит клиентов на одного `user`?

**Предложение:** без лимита в v1. Config `MAX_CLIENTS_PER_USER` — при необходимости позже.

### C. `/status` для `user`

**Предложение:** без изменений — общий статус WireGuard. Не раскрывает чужие имена/IP. Скрывать aggregate stats для user — только если попросите отдельно.

---

## Закрытые вопросы

1. user видит только своих → **да**
2. admin видит всех + владелец на карточке → **да**
3. legacy admin-only навсегда → **да**
4. orphan admin-only → **да**
5. user может создавать (➕ Клиент) → **да**
6. admin manage всех → **да**

---

## Связь с TODO

- Не дублирует security items #5–#13
- Усиливает #11 (audit log) — желательно делать вместе с PR2
- #7 (private chat only) — актуально сильнее, если user получит create (`.conf`/QR)
