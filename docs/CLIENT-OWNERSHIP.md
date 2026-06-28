# Client ownership — проектирование

**Статус:** draft, без реализации  
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

Ownership **нигде не хранится**: в `{name}.json` есть `name`, `pubkey`, `client_ip`, `created_at`, но нет `created_by`.

---

## Варианты модели

### A. Owner только в local meta (рекомендуется для v1)

При `save_client()` записывать в JSON:

```json
{
  "name": "alice",
  "pubkey": "...",
  "created_by": 123456789,
  "created_at": "..."
}
```

**Проверка прав:** перед create/rotate/delete — `can_manage_client(actor_id, client)`.

| Роль | Правило |
|------|---------|
| `superadmin` | любой клиент |
| `admin` | любой клиент (или только свои — см. вопросы) |
| `user` | только `created_by == actor_id` |

**Плюсы:** минимальные изменения, не зависит от wg-admin.  
**Минусы:** orphan peer (нет local `.json`) — owner неизвестен; старые клиенты без `created_by`.

### B. Owner в wg-admin `peer.description`

Кодировать owner в description, например `alice@123456789` или JSON.

**Минусы:** ломает человекочитаемые имена; wg-admin — общий источник правды для orphan; сложнее миграция.

**Не рекомендуется** при текущей архитектуре (description = storage name для local clients).

### C. Отдельный index-файл `owners.json`

`pubkey → operator_id` в state dir.

**Плюсы:** быстрый lookup по pubkey для orphan после первого «claim».  
**Минусы:** второй источник правды, рассинхрон с meta.

---

## Рекомендация: A + правила для legacy/orphan

### `can_manage_client(actor, client) -> bool`

```text
superadmin                          → true
admin + policy "admin_sees_all"     → true   # default ON для обратной совместимости
admin + policy "admin_own_only"     → created_by == actor
user                                → created_by == actor
client without created_by (legacy)  → admin/superadmin only
orphan (no local conf)              → admin/superadmin only (как сейчас)
```

### `can_view_client(actor, client) -> bool`

**Вариант 1 (проще):** `user` по-прежнему видит **всех** в списке, но кнопки manage только на своих.  
**Вариант 2 (строже):** `user` видит в списке **только своих** (+ опционально stats по всем для support).

Нужно выбрать (см. вопросы ниже).

---

## Изменения по слоям (когда будем делать)

### `client_manager.py`

- `save_client(..., created_by: int)`
- `load_client` → поле `created_by` (optional)
- helper `client_owned_by(record, operator_id)`

### `service.py`

- `create_client(name, *, actor_id)` — прокидывает `created_by`
- `list_clients_merged()` — добавляет `created_by` в dict (из meta; для orphan `None`)
- `delete_client` / `rotate_client` — проверка через `can_manage_client`

### `main.py`

- Передавать `message.from_user.id` / `callback.from_user.id` во все mutating операции
- Фильтр списка (если выбран strict view)
- `client_actions_keyboard(..., can_manage: bool)` — rotate/remove только если manage
- Для `user`: показать **➕ Клиент** в reply-меню (сейчас только admin)

### `users.py` / config

- Опционально: флаг `ADMIN_MANAGES_ALL_CLIENTS=true` (default true)
- Без флага admin ограничен своими клиентами (редкий режим)

### Миграция

| Категория | Поведение |
|-----------|-----------|
| Существующие `.json` без `created_by` | `created_by = null` → manage только admin/superadmin; view — по политике |
| Одноразовая команда `/claim` или скрипт | superadmin проставляет owner для legacy (optional) |
| Orphan peer | без изменений: delete через admin по pubkey, owner не назначается |

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
- `created_by` в meta — не доверять для проверки без загрузки meta по `storage_name` (уже есть pubkey lookup)
- Audit log (TODO #11): `{actor, action, client, pubkey}` — особенно важен при shared admin pool

---

## Объём работ (оценка)

| PR | Содержание |
|----|------------|
| PR1 | `created_by` в meta + `create_client(actor_id)` + тесты |
| PR2 | `can_manage_client` + guards на rotate/delete + UI кнопки |
| PR3 | Меню ➕ Клиент для `user` + фильтр списка (если strict) |
| PR4 | Legacy migration / документация / config flag |

---

## Открытые вопросы (нужно решить до реализации)

1. **`user` видит чужих клиенты в списке или только своих?**  
   - Только свои — проще mentally, меньше утечки имён/IP.  
   - Все — удобнее для «я вижу что на сервере, но трогать могу только своё».

2. **`admin` управляет всеми клиентами или только своими?**  
   - Default: **всеми** (как сейчас), иначе ломается текущий ops-workflow.  
   - Restricted admin — отдельный режим через config.

3. **Кто может создавать клиентов после фичи?**  
   - `user` + admin + superadmin (ожидаемо)  
   - или user только если admin явно выдал quota (overkill для v1)?

4. **Legacy-клиенты без `created_by`:**  
   - навсегда admin-only manage  
   - или разовый claim/migration superadmin'ом?

5. **Orphan peer с чужим description:**  
   - оставить admin-only (рекомендуется)  
   - или позволить user «adopt» orphan (сложно, рискованно)?

---

## Связь с TODO

- Не дублирует security items #5–#13
- Усиливает #11 (audit log) — желательно делать вместе с PR2
- #7 (private chat only) — актуально сильнее, если user получит create (`.conf`/QR)
