import json
import os
import tempfile
from typing import List, Dict


class UserManagerError(Exception):
    """Ошибки при управлении пользователями."""


class UserManager:
    def __init__(self, path: str, superadmins: List[int] = None):
        self.path = path
        self.superadmins = set(superadmins or [])
        self._users: List[Dict] = []
        self.load()

    # --- utils ---
    def _atomic_write(self, data: str):
        """Записывает строку в файл атомарно (через временный файл)."""
        dir_name = os.path.dirname(self.path) or "."
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name
        os.replace(tmp_name, self.path)

    def load(self):
        """Загружает пользователей из JSON файла."""
        if not os.path.exists(self.path):
            self._users = []
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._users = json.load(f)
        except Exception as e:
            raise UserManagerError(f"Ошибка загрузки {self.path}: {e}")

    def save(self):
        """Сохраняет пользователей в JSON файл атомарно."""
        try:
            data = json.dumps(self._users, indent=2, ensure_ascii=False)
            self._atomic_write(data)
        except Exception as e:
            raise UserManagerError(f"Ошибка записи {self.path}: {e}")

    # --- access checks ---
    def is_admin(self, user_id: int) -> bool:
        return (
            user_id in self.superadmins
            or any(u["id"] == user_id and u["role"] == "admin" for u in self._users)
        )

    def is_user(self, user_id: int) -> bool:
        return user_id in self.superadmins or any(u["id"] == user_id for u in self._users)

    # --- user management ---
    def list_users(self) -> List[Dict]:
        """Возвращает список всех пользователей (включая супер-админов)."""
        users = list(self._users)
        for sa in self.superadmins:
            if not any(u["id"] == sa for u in users):
                users.append({"id": sa, "role": "superadmin"})
        return users

    def add_user(self, user_id: int, role: str):
        if role not in ("admin", "user"):
            raise UserManagerError("Роль должна быть 'admin' или 'user'")
        if any(u["id"] == user_id for u in self._users) or user_id in self.superadmins:
            raise UserManagerError("Пользователь уже существует")
        self._users.append({"id": user_id, "role": role})
        self.save()

    def remove_user(self, user_id: int):
        if user_id in self.superadmins:
            raise UserManagerError("Нельзя удалить супер-админа из конфига")
        before = len(self._users)
        self._users = [u for u in self._users if u["id"] != user_id]
        if len(self._users) == before:
            raise UserManagerError("Пользователь не найден")
        self.save()
