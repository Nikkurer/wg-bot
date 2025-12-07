# Unit-тесты для wg-bot

Этот каталог содержит unit-тесты для проекта wg-bot, написанные с использованием pytest.

## Структура

- `test_users.py` - тесты для модуля `users.py` (UserManager)
- `test_wg_manager.py` - тесты для модуля `wg_manager.py` (WGManager)
- `conftest.py` - конфигурация pytest и общие фикстуры

## Установка зависимостей

```bash
# Установка pytest
pip install pytest

# Или через uv
uv pip install pytest
```

## Запуск тестов

```bash
# Запуск всех тестов
pytest

# Запуск с подробным выводом
pytest -v

# Запуск конкретного файла тестов
pytest tests/test_users.py

# Запуск конкретного теста
pytest tests/test_users.py::TestUserManager::test_add_user_success

# Запуск с выводом print statements
pytest -s

# Запуск с остановкой на первой ошибке
pytest -x
```

## Покрытие кода

Для установки pytest-cov:

```bash
pip install pytest-cov
```

Запуск с покрытием:

```bash
# Терминальный вывод
pytest --cov=. --cov-report=term-missing

# HTML отчёт
pytest --cov=. --cov-report=html
# Отчёт будет в htmlcov/index.html
```

## Структура тестов

Тесты используют:
- **Фикстуры pytest** для создания тестовых данных
- **Моки (unittest.mock)** для изоляции зависимостей
- **Временные файлы и директории** для каждого теста
- **pytest.raises** для проверки исключений

## Примеры тестов

### Тесты для UserManager
- Инициализация и загрузка пользователей
- Проверка прав доступа (is_admin, is_user)
- Добавление и удаление пользователей
- Сохранение и загрузка данных

### Тесты для WGManager
- Выполнение команд через subprocess
- Генерация ключей
- Атомарная запись файлов
- Управление клиентами (добавление, удаление, список)
- Получение статистики пиров
- Санитизация вывода статуса

