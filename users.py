import json
import os
import tempfile
from typing import List, Dict, Optional

from operator_add import profile_from_fields

_VALID_ROLES = frozenset({"admin", "user"})
_PROFILE_KEYS = frozenset({"first_name", "last_name", "username"})
_ALLOWED_KEYS = frozenset({"id", "role"}) | _PROFILE_KEYS


def _validate_user_record(record, index: int) -> Dict:
    if not isinstance(record, dict):
        raise UserManagerError(
            f"Запись {index}: ожидается объект, получено {type(record).__name__}"
        )
    unknown = set(record.keys()) - _ALLOWED_KEYS
    if unknown:
        raise UserManagerError(
            f"Запись {index}: неизвестные поля: {', '.join(sorted(unknown))}"
        )
    if "id" not in record or "role" not in record:
        raise UserManagerError(f"Запись {index}: обязательные поля id и role")
    user_id = record["id"]
    if type(user_id) is not int:
        raise UserManagerError(f"Запись {index}: id должен быть int")
    role = record["role"]
    if not isinstance(role, str) or role not in _VALID_ROLES:
        raise UserManagerError(
            f"Запись {index}: роль должна быть 'admin' или 'user'"
        )
    for key in _PROFILE_KEYS:
        if key in record and not isinstance(record[key], str):
            raise UserManagerError(f"Запись {index}: {key} должен быть строкой")
    return record


def _validate_users(data, path: str) -> List[Dict]:
    if not isinstance(data, list):
        raise UserManagerError(f"Ожидается JSON-массив в {path}")
    seen_ids: set[int] = set()
    validated: List[Dict] = []
    for index, record in enumerate(data):
        entry = _validate_user_record(record, index)
        user_id = entry["id"]
        if user_id in seen_ids:
            raise UserManagerError(f"Запись {index}: дублирующийся id {user_id}")
        seen_ids.add(user_id)
        validated.append(entry)
    return validated


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
    def _atomic_write(self, data: str, mode: int = 0o600) -> None:
        """Атомарно записывает строку в файл с заданными правами доступа."""
        if os.path.exists(self.path) and os.path.islink(self.path):
            raise UserManagerError("Refusing to overwrite symlink")
        dir_name = os.path.dirname(self.path) or "."
        base_name = os.path.basename(self.path)
        fd, tmp_path = tempfile.mkstemp(prefix=base_name, dir=dir_name, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

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
                raw = json.load(f)
            self._users = _validate_users(raw, self.path)
        except UserManagerError:
            raise
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
    def is_superadmin(self, user_id: int) -> bool:
        """True if user_id is listed in config ALLOWED_USERS."""
        return user_id in self.superadmins

    def get_user(self, user_id: int) -> Optional[Dict]:
        for u in self._users:
            if u["id"] == user_id:
                return u
        return None

    def can_manage_operator(self, actor_id: int, target: Dict) -> bool:
        """Whether actor may remove target operator (not superadmin from config)."""
        role = target.get("role")
        if role == "superadmin":
            return False
        if role == "admin":
            return self.is_superadmin(actor_id)
        return self.is_admin(actor_id)

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

    def add_user(
        self,
        user_id: int,
        role: str,
        *,
        actor_id: Optional[int] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
    ):
        """Добавляет нового пользователя.

        Args:
            user_id (int): ID пользователя Telegram.
            role (str): Роль пользователя. Должна быть "admin" или "user".
            actor_id (int, optional): ID оператора, выполняющего добавление.
            first_name (str, optional): Имя из Telegram-профиля.
            last_name (str, optional): Фамилия из Telegram-профиля.
            username (str, optional): Username без @.

        Raises:
            UserManagerError: Если роль невалидна, пользователь уже существует
                или является супер-администратором.
        """
        if role not in ("admin", "user"):
            raise UserManagerError("Роль должна быть 'admin' или 'user'")
        if (
            role == "admin"
            and actor_id is not None
            and not self.is_superadmin(actor_id)
        ):
            raise UserManagerError("Только superadmin может назначать роль admin")
        if any(u["id"] == user_id for u in self._users) or user_id in self.superadmins:
            raise UserManagerError("Пользователь уже существует")
        record: Dict = {"id": user_id, "role": role}
        record.update(
            profile_from_fields(
                first_name=first_name,
                last_name=last_name,
                username=username,
            )
        )
        self._users.append(record)
        self.save()

    def update_user_profile(
        self,
        user_id: int,
        *,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
    ) -> bool:
        """Обновляет отображаемый профиль оператора в users.json."""
        for u in self._users:
            if u["id"] != user_id:
                continue
            if first_name:
                u["first_name"] = first_name
            if last_name:
                u["last_name"] = last_name
            if username:
                u["username"] = username.lstrip("@")
            self.save()
            return True
        return False

    def remove_user(self, user_id: int, *, actor_id: Optional[int] = None):
        """Удаляет пользователя из списка.

        Args:
            user_id (int): ID пользователя Telegram для удаления.
            actor_id (int, optional): ID оператора, выполняющего удаление.

        Raises:
            UserManagerError: Если пользователь является супер-администратором
                или не найден в списке.
        """
        if user_id in self.superadmins:
            raise UserManagerError("Нельзя удалить супер-админа из конфига")
        target = self.get_user(user_id)
        if target is None:
            raise UserManagerError("Пользователь не найден")
        if actor_id is not None and not self.can_manage_operator(actor_id, target):
            if target.get("role") == "admin":
                raise UserManagerError("Только superadmin может удалять admin")
            raise UserManagerError("Недостаточно прав для удаления оператора")
        self._users = [u for u in self._users if u["id"] != user_id]
        self.save()
