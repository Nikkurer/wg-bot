import json
import os
import tempfile
from typing import List, Dict


class UserManagerError(Exception):
    """Исключение для ошибок управления пользователями бота.

    Используется для обработки ошибок при работе с пользователями,
    их ролями и правами доступа.
    """


class UserManager:
    """Менеджер для управления пользователями Telegram-бота.

    Предоставляет функциональность для управления пользователями,
    их ролями (admin, user) и проверки прав доступа.
    """

    def __init__(self, path: str, superadmins: List[int] = None):
        """Инициализирует менеджер пользователей.

        Args:
            path (str): Путь к JSON файлу для хранения пользователей.
            superadmins (List[int], optional): Список ID супер-администраторов.
                По умолчанию None (пустой список).
        """
        self.path = path
        self.superadmins = set(superadmins or [])
        self._users: List[Dict] = []
        self.load()

    # --- utils ---
    def _atomic_write(self, data: str):
        """Атомарно записывает строку в файл.

        Создаёт временный файл, записывает данные, синхронизирует на диск
        и затем атомарно заменяет целевой файл. Это предотвращает повреждение
        данных при сбоях во время записи.

        Args:
            data (str): Данные для записи в файл.

        Raises:
            OSError: Если произошла ошибка при записи или замене файла.
        """
        dir_name = os.path.dirname(self.path) or "."
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name
        os.replace(tmp_name, self.path)

    def load(self):
        """Загружает пользователей из JSON файла.

        Если файл не существует, инициализирует пустой список пользователей.

        Raises:
            UserManagerError: Если произошла ошибка при чтении или парсинге JSON.
        """
        if not os.path.exists(self.path):
            self._users = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._users = json.load(f)
        except Exception as e:
            raise UserManagerError(f"Ошибка загрузки {self.path}: {e}")

    def save(self):
        """Сохраняет пользователей в JSON файл атомарно.

        Raises:
            UserManagerError: Если произошла ошибка при записи файла.
        """
        try:
            data = json.dumps(self._users, indent=2, ensure_ascii=False)
            self._atomic_write(data)
        except Exception as e:
            raise UserManagerError(f"Ошибка записи {self.path}: {e}")

    # --- access checks ---
    def is_admin(self, user_id: int) -> bool:
        """Проверяет, является ли пользователь администратором.

        Args:
            user_id (int): ID пользователя Telegram.

        Returns:
            bool: True если пользователь является супер-админом или имеет роль "admin".
        """
        return (
            user_id in self.superadmins
            or any(u["id"] == user_id and u["role"] == "admin" for u in self._users)
        )

    def is_user(self, user_id: int) -> bool:
        """Проверяет, является ли пользователь зарегистрированным пользователем.

        Args:
            user_id (int): ID пользователя Telegram.

        Returns:
            bool: True если пользователь является супер-админом или зарегистрирован
                в списке пользователей.
        """
        return user_id in self.superadmins or any(u["id"] == user_id for u in self._users)

    # --- user management ---
    def list_users(self) -> List[Dict]:
        """Возвращает список всех пользователей.

        Включает как обычных пользователей из файла, так и супер-администраторов
        из конфигурации.

        Returns:
            List[Dict]: Список словарей с информацией о пользователях:
                - id (int): ID пользователя Telegram
                - role (str): Роль пользователя ("admin", "user" или "superadmin")
        """
        users = list(self._users)
        for sa in self.superadmins:
            if not any(u["id"] == sa for u in users):
                users.append({"id": sa, "role": "superadmin"})
        return users

    def add_user(self, user_id: int, role: str):
        """Добавляет нового пользователя.

        Args:
            user_id (int): ID пользователя Telegram.
            role (str): Роль пользователя. Должна быть "admin" или "user".

        Raises:
            UserManagerError: Если роль невалидна, пользователь уже существует
                или является супер-администратором.
        """
        if role not in ("admin", "user"):
            raise UserManagerError("Роль должна быть 'admin' или 'user'")
        if any(u["id"] == user_id for u in self._users) or user_id in self.superadmins:
            raise UserManagerError("Пользователь уже существует")
        self._users.append({"id": user_id, "role": role})
        self.save()

    def remove_user(self, user_id: int):
        """Удаляет пользователя из списка.

        Args:
            user_id (int): ID пользователя Telegram для удаления.

        Raises:
            UserManagerError: Если пользователь является супер-администратором
                или не найден в списке.
        """
        if user_id in self.superadmins:
            raise UserManagerError("Нельзя удалить супер-админа из конфига")
        before = len(self._users)
        self._users = [u for u in self._users if u["id"] != user_id]
        if len(self._users) == before:
            raise UserManagerError("Пользователь не найден")
        self.save()
