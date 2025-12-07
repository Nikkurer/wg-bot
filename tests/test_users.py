"""Unit tests for users.py module using pytest."""
import json
import os
import tempfile

import pytest

from users import UserManager, UserManagerError


@pytest.fixture
def temp_user_file():
    """Создаёт временный файл для тестов."""
    temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json")
    # Создаём файл с пустым JSON массивом, чтобы избежать ошибок загрузки
    temp_file.write("[]")
    temp_file.close()
    yield temp_file.name
    if os.path.exists(temp_file.name):
        os.remove(temp_file.name)


@pytest.fixture
def user_manager(temp_user_file):
    """Создаёт экземпляр UserManager для тестов."""
    return UserManager(temp_user_file, superadmins=[123456789])


class TestUserManager:
    """Тесты для класса UserManager."""

    def test_init_creates_empty_list(self, user_manager):
        """Тест: инициализация создаёт пустой список пользователей."""
        assert len(user_manager._users) == 0
        assert 123456789 in user_manager.superadmins

    def test_init_loads_existing_users(self, temp_user_file):
        """Тест: инициализация загружает существующих пользователей."""
        existing_users = [{"id": 111, "role": "user"}, {"id": 222, "role": "admin"}]
        with open(temp_user_file, "w", encoding="utf-8") as f:
            json.dump(existing_users, f)

        manager = UserManager(temp_user_file, superadmins=[123456789])
        assert len(manager._users) == 2
        assert manager._users[0]["id"] == 111

    def test_is_admin_superadmin(self, user_manager):
        """Тест: супер-админ считается администратором."""
        assert user_manager.is_admin(123456789) is True

    def test_is_admin_role_admin(self, user_manager):
        """Тест: пользователь с ролью admin считается администратором."""
        user_manager.add_user(999, "admin")
        assert user_manager.is_admin(999) is True

    def test_is_admin_role_user(self, user_manager):
        """Тест: пользователь с ролью user не является администратором."""
        user_manager.add_user(888, "user")
        assert user_manager.is_admin(888) is False

    def test_is_user_superadmin(self, user_manager):
        """Тест: супер-админ считается пользователем."""
        assert user_manager.is_user(123456789) is True

    def test_is_user_registered(self, user_manager):
        """Тест: зарегистрированный пользователь считается пользователем."""
        user_manager.add_user(777, "user")
        assert user_manager.is_user(777) is True

    def test_is_user_not_registered(self, user_manager):
        """Тест: незарегистрированный пользователь не считается пользователем."""
        assert user_manager.is_user(999999) is False

    def test_add_user_success(self, user_manager):
        """Тест: успешное добавление пользователя."""
        user_manager.add_user(111, "user")
        assert len(user_manager._users) == 1
        assert user_manager._users[0]["id"] == 111
        assert user_manager._users[0]["role"] == "user"

    def test_add_user_invalid_role(self, user_manager):
        """Тест: добавление пользователя с невалидной ролью вызывает ошибку."""
        with pytest.raises(UserManagerError, match="Роль должна быть"):
            user_manager.add_user(111, "invalid_role")

    def test_add_user_already_exists(self, user_manager):
        """Тест: добавление существующего пользователя вызывает ошибку."""
        user_manager.add_user(111, "user")
        with pytest.raises(UserManagerError, match="уже существует"):
            user_manager.add_user(111, "admin")

    def test_add_user_superadmin_exists(self, user_manager):
        """Тест: добавление супер-админа вызывает ошибку."""
        with pytest.raises(UserManagerError, match="уже существует"):
            user_manager.add_user(123456789, "user")

    def test_remove_user_success(self, user_manager):
        """Тест: успешное удаление пользователя."""
        user_manager.add_user(111, "user")
        user_manager.remove_user(111)
        assert len(user_manager._users) == 0
        assert user_manager.is_user(111) is False

    def test_remove_user_not_found(self, user_manager):
        """Тест: удаление несуществующего пользователя вызывает ошибку."""
        with pytest.raises(UserManagerError, match="не найден"):
            user_manager.remove_user(999)

    def test_remove_user_superadmin(self, user_manager):
        """Тест: удаление супер-админа вызывает ошибку."""
        with pytest.raises(UserManagerError, match="супер-админа"):
            user_manager.remove_user(123456789)

    def test_list_users_includes_superadmins(self, user_manager):
        """Тест: список пользователей включает супер-админов."""
        user_manager.add_user(111, "user")
        users = user_manager.list_users()
        assert len(users) == 2  # 1 обычный + 1 супер-админ
        user_ids = [u["id"] for u in users]
        assert 123456789 in user_ids
        assert 111 in user_ids

    def test_list_users_superadmin_role(self, user_manager):
        """Тест: супер-админ имеет роль superadmin в списке."""
        users = user_manager.list_users()
        superadmin = next(u for u in users if u["id"] == 123456789)
        assert superadmin["role"] == "superadmin"

    def test_save_and_load_persistence(self, temp_user_file):
        """Тест: сохранение и загрузка сохраняют данные."""
        manager1 = UserManager(temp_user_file, superadmins=[123456789])
        manager1.add_user(111, "admin")
        manager1.add_user(222, "user")

        # Создаём новый менеджер с тем же файлом
        manager2 = UserManager(temp_user_file, superadmins=[123456789])
        assert len(manager2._users) == 2
        assert manager2.is_admin(111) is True
        assert manager2.is_user(222) is True

