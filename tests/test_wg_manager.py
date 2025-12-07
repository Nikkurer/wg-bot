"""Unit tests for wg_manager.py module using pytest."""
import json
import os
import shutil
import subprocess
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from wg_manager import WGManager, WGManagerError


@pytest.fixture(scope="function")
def temp_dir():
    """Создаёт временную директорию для тестов."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Очищаем директорию перед удалением
    if os.path.exists(temp_dir):
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(temp_dir)


@pytest.fixture
def mock_logger():
    """Создаёт мок логгера."""
    return MagicMock()


@pytest.fixture(scope="function")
def wg_manager(temp_dir, mock_logger):
    """Создаёт экземпляр WGManager для тестов."""
    with patch("wg_manager.os.getuid", return_value=1000), patch(
        "wg_manager.os.makedirs"
    ), patch("wg_manager.os.stat") as mock_stat:
        mock_stat.return_value.st_uid = 1000
        mock_stat.return_value.st_mode = 0o700  # Безопасные права

        manager = WGManager(
            wg_iface="wg0",
            client_dir=temp_dir,
            wg_subnet="10.10.0.0/24",
            server_public_key="test_server_key",
            logger=mock_logger,
        )
        return manager


class TestWGManagerError:
    """Тесты для класса WGManagerError."""

    def test_init_without_logger(self):
        """Тест: инициализация без логгера работает."""
        error = WGManagerError("Test error")
        assert str(error) == "Test error"
        assert error._extra == {}

    def test_init_with_logger(self):
        """Тест: инициализация с логгером записывает ошибку."""
        mock_logger = MagicMock()
        error = WGManagerError("Test error", logger=mock_logger)
        mock_logger.error.assert_called_once()
        assert "Test error" in mock_logger.error.call_args[0][0]

    def test_init_with_extra(self):
        """Тест: инициализация с дополнительными данными сохраняет их."""
        error = WGManagerError("Test error", stderr="some error")
        assert error._extra.get("stderr") == "some error"


class TestWGManager:
    """Тесты для класса WGManager."""

    def test_run_success(self, wg_manager):
        """Тест: успешное выполнение команды."""
        with patch("wg_manager.subprocess.run") as mock_run:
            mock_proc = Mock()
            mock_proc.stdout = "test output\n"
            mock_proc.returncode = 0
            mock_run.return_value = mock_proc

            result = wg_manager._run(["test", "command"])
            assert result == "test output"
            mock_run.assert_called_once()

    def test_run_failure(self, wg_manager):
        """Тест: ошибка выполнения команды вызывает исключение."""
        with patch("wg_manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "test", stderr="error message"
            )

            with pytest.raises(WGManagerError):
                wg_manager._run(["test", "command"])

    def test_gen_keypair(self, wg_manager):
        """Тест: генерация пары ключей."""
        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = "private_key"

            with patch("wg_manager.subprocess.run") as mock_subprocess:
                mock_proc = Mock()
                mock_proc.stdout = "public_key\n"
                mock_proc.returncode = 0
                mock_subprocess.return_value = mock_proc

                priv, pub = wg_manager._gen_keypair()

                assert priv == "private_key"
                assert pub == "public_key"
                mock_run.assert_called_once_with(["sudo", "wg", "genkey"])
                mock_subprocess.assert_called_once()

    def test_atomic_write(self, wg_manager, temp_dir):
        """Тест: атомарная запись файла."""
        test_path = os.path.join(temp_dir, "test.txt")
        test_data = "test content"

        wg_manager._atomic_write(test_path, test_data, mode=0o600)

        assert os.path.exists(test_path)
        with open(test_path, "r", encoding="utf-8") as f:
            assert f.read() == test_data

        # Проверяем права доступа
        stat = os.stat(test_path)
        assert stat.st_mode & 0o777 == 0o600

    def test_atomic_write_refuses_symlink(self, wg_manager, temp_dir):
        """Тест: атомарная запись отказывается перезаписывать симлинк."""
        test_path = os.path.join(temp_dir, "test.txt")
        os.symlink("/dev/null", test_path)

        with pytest.raises(WGManagerError):
            wg_manager._atomic_write(test_path, "data")

    def test_list_used_ips_from_files(self, wg_manager, temp_dir):
        """Тест: получение используемых IP из файлов клиентов."""
        # Создаём тестовые файлы клиентов
        client1_path = os.path.join(temp_dir, "client1.json")
        with open(client1_path, "w", encoding="utf-8") as f:
            json.dump({"client_ip": "10.10.0.2/24"}, f)

        client2_path = os.path.join(temp_dir, "client2.json")
        with open(client2_path, "w", encoding="utf-8") as f:
            json.dump({"client_ip": "10.10.0.3/24"}, f)

        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = ""

            used_ips = wg_manager._list_used_ips()
            assert "10.10.0.2" in used_ips
            assert "10.10.0.3" in used_ips

    def test_list_used_ips_from_wg_dump(self, wg_manager):
        """Тест: получение используемых IP из вывода wg dump."""
        with patch.object(wg_manager, "_run") as mock_run:
            # Код проверяет len(cols) >= 9 и берёт allowed_ips из cols[8]
            # Создаём формат с минимум 9 колонками, где allowed_ips в колонке 8
            mock_run.return_value = (
                "interface_data\tkey1\tkey2\t51820\t0\n"
                "peer_key\tpsk\tendpoint\tcol3\tcol4\tcol5\tcol6\tcol7\t10.10.0.5/32\tcol9\n"
            )

            used_ips = wg_manager._list_used_ips()
            assert "10.10.0.5" in used_ips

    def test_next_free_ip(self, wg_manager):
        """Тест: получение следующего свободного IP."""
        with patch.object(wg_manager, "_list_used_ips") as mock_list_used:
            mock_list_used.return_value = {"10.10.0.2", "10.10.0.3"}

            free_ip = wg_manager._next_free_ip()
            # Первый свободный IP в подсети 10.10.0.0/24 - это 10.10.0.1 (первый хост)
            assert free_ip == "10.10.0.1/24"

    def test_next_free_ip_no_free(self, wg_manager):
        """Тест: отсутствие свободных IP вызывает ошибку."""
        with patch.object(wg_manager, "_list_used_ips") as mock_list_used:
            # Заполняем все IP в подсети /24 (254 хоста: от 10.10.0.1 до 10.10.0.254)
            used = {f"10.10.0.{i}" for i in range(1, 255)}
            mock_list_used.return_value = used

            with pytest.raises(WGManagerError, match="No free IPs"):
                wg_manager._next_free_ip()

    def test_add_client_success(self, wg_manager, temp_dir):
        """Тест: успешное добавление клиента."""
        with patch.object(wg_manager, "_gen_keypair") as mock_genkey, patch.object(
            wg_manager, "_next_free_ip"
        ) as mock_next_ip, patch.object(wg_manager, "_run") as mock_run:
            mock_genkey.return_value = ("private_key", "public_key")
            mock_next_ip.return_value = "10.10.0.2/24"
            mock_run.return_value = ""  # wg set успешно

            result = wg_manager.add_client("testclient")

            assert result["name"] == "testclient"
            assert result["client_ip"] == "10.10.0.2/24"
            assert result["pubkey"] == "public_key"

            # Проверяем, что файлы созданы
            meta_path = os.path.join(temp_dir, "testclient.json")
            conf_path = os.path.join(temp_dir, "testclient.conf")
            assert os.path.exists(meta_path)
            assert os.path.exists(conf_path)

            # Проверяем содержимое метаданных
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            assert meta["name"] == "testclient"
            assert meta["pubkey"] == "public_key"

            # Проверяем, что wg set был вызван
            mock_run.assert_called()
            assert "wg" in mock_run.call_args[0][0]

    def test_add_client_invalid_name(self, wg_manager):
        """Тест: добавление клиента с невалидным именем вызывает ошибку."""
        with pytest.raises(WGManagerError, match="Invalid client name"):
            wg_manager.add_client("invalid name!")

    def test_add_client_already_exists(self, wg_manager, temp_dir):
        """Тест: добавление существующего клиента вызывает ошибку."""
        # Создаём существующий файл
        meta_path = os.path.join(temp_dir, "existing.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({}, f)

        with pytest.raises(WGManagerError, match="already exists"):
            wg_manager.add_client("existing")

    def test_remove_client_success(self, wg_manager, temp_dir):
        """Тест: успешное удаление клиента."""
        # Создаём тестового клиента
        meta_path = os.path.join(temp_dir, "testclient.json")
        conf_path = os.path.join(temp_dir, "testclient.conf")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "testclient",
                    "pubkey": "test_pubkey",
                    "conf_path": conf_path,
                },
                f,
            )
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write("test config")

        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = ""
            result = wg_manager.remove_client("testclient")

        assert result is True
        assert not os.path.exists(meta_path)
        assert not os.path.exists(conf_path)

    def test_remove_client_not_found(self, wg_manager):
        """Тест: удаление несуществующего клиента вызывает ошибку."""
        with pytest.raises(WGManagerError, match="not found"):
            wg_manager.remove_client("nonexistent")

    def test_list_clients(self, wg_manager, temp_dir):
        """Тест: получение списка клиентов."""
        # Создаём тестовых клиентов
        client1_path = os.path.join(temp_dir, "client1.json")
        with open(client1_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "client1",
                    "client_ip": "10.10.0.2/24",
                    "pubkey": "pubkey1",
                },
                f,
            )

        client2_path = os.path.join(temp_dir, "client2.json")
        with open(client2_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "client2",
                    "client_ip": "10.10.0.3/24",
                    "pubkey": "pubkey2",
                },
                f,
            )

        clients = wg_manager.list_clients()
        assert len(clients) == 2
        client_names = [c["name"] for c in clients]
        assert "client1" in client_names
        assert "client2" in client_names

    def test_peer_stats(self, wg_manager, temp_dir):
        """Тест: получение статистики пира."""
        # Создаём метаданные клиента
        meta_path = os.path.join(temp_dir, "testclient.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"name": "testclient", "pubkey": "test_pubkey"}, f)

        # Мокаем wg dump
        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = (
                "interface_data\tkey1\tkey2\t51820\t0\n"
                "test_pubkey\tpsk\t192.168.1.1:51820\t10.10.0.2/32\t1234567890\t1000\t2000\t25\n"
            )

            stats = wg_manager.peer_stats("testclient")
            assert stats["pubkey"] == "test_pubkey"
            assert stats["endpoint"] == "192.168.1.1:51820"
            assert stats["allowed_ips"] == "10.10.0.2/32"
            assert stats["rx_bytes"] == "1000"
            assert stats["tx_bytes"] == "2000"

    def test_peer_stats_not_found(self, wg_manager, temp_dir):
        """Тест: статистика несуществующего пира вызывает ошибку."""
        meta_path = os.path.join(temp_dir, "testclient.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"name": "testclient", "pubkey": "test_pubkey"}, f)

        # Мокаем wg dump без нужного пира
        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = "interface_data\tkey1\tkey2\t51820\t0\n"

            with pytest.raises(WGManagerError, match="not found"):
                wg_manager.peer_stats("testclient")

    def test_status(self, wg_manager):
        """Тест: получение статуса с санитизацией."""
        with patch.object(wg_manager, "_run") as mock_run:
            mock_run.return_value = (
                "private_key\tpublic_key\t51820\t0\n"
                "peer_pubkey\tpreshared_key\tendpoint\t10.10.0.2/32\t0\t0\t0\t0\n"
            )

            status = wg_manager.status()
            assert "<REDACTED>" in status  # Приватный ключ скрыт
            assert "peer_pubkey" in status  # Публичный ключ пира виден
            # Проверяем, что preshared key тоже скрыт
            lines = status.split("\n")
            peer_line = lines[1] if len(lines) > 1 else ""
            assert "<REDACTED>" in peer_line or "preshared_key" not in peer_line

    def test_parse_config_peers_single_client(self, wg_manager):
        """Тест: парсинг конфига с одним клиентом."""
        config_content = """# BEGIN_PEER client1
[Peer]
PublicKey = test_pubkey_1
AllowedIPs = 10.10.0.2/32
PresharedKey = test_psk_1
# END_PEER client1
"""
        clients = wg_manager._parse_config_peers(config_content)
        assert len(clients) == 1
        assert "client1" in clients
        assert clients["client1"]["PublicKey"] == "test_pubkey_1"
        assert clients["client1"]["AllowedIPs"] == "10.10.0.2/32"
        assert clients["client1"]["PresharedKey"] == "test_psk_1"

    def test_parse_config_peers_multiple_clients(self, wg_manager):
        """Тест: парсинг конфига с несколькими клиентами."""
        config_content = """# BEGIN_PEER client1
[Peer]
PublicKey = pubkey1
AllowedIPs = 10.10.0.2/32
# END_PEER client1

# BEGIN_PEER client2
[Peer]
PublicKey = pubkey2
AllowedIPs = 10.10.0.3/32
PresharedKey = psk2
# END_PEER client2
"""
        clients = wg_manager._parse_config_peers(config_content)
        assert len(clients) == 2
        assert "client1" in clients
        assert "client2" in clients
        assert clients["client1"]["PublicKey"] == "pubkey1"
        assert clients["client2"]["PublicKey"] == "pubkey2"
        assert "PresharedKey" not in clients["client1"]
        assert clients["client2"]["PresharedKey"] == "psk2"

    def test_parse_config_peers_no_clients(self, wg_manager):
        """Тест: парсинг конфига без клиентов."""
        config_content = "[Interface]\nPrivateKey = server_key\n"
        clients = wg_manager._parse_config_peers(config_content)
        assert len(clients) == 0

    def test_parse_config_peers_malformed(self, wg_manager):
        """Тест: парсинг конфига с неправильным форматом."""
        # BEGIN_PEER без END_PEER
        config_content = """# BEGIN_PEER client1
[Peer]
PublicKey = pubkey1
"""
        clients = wg_manager._parse_config_peers(config_content)
        # Неполная секция не должна быть добавлена
        assert len(clients) == 0

    def test_sync_from_single_config_create_new(self, wg_manager, temp_dir):
        """Тест: синхронизация создаёт нового клиента."""
        config_path = os.path.join(temp_dir, "test.conf")
        config_content = """# BEGIN_PEER newclient
[Peer]
PublicKey = new_pubkey
AllowedIPs = 10.10.0.5/32
PresharedKey = new_psk
# END_PEER newclient
"""
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        with patch.object(wg_manager, "_next_free_ip") as mock_next_ip:
            mock_next_ip.return_value = "10.10.0.5/24"

            result = wg_manager._sync_from_single_config(config_path)

            assert result["created"] == 1
            assert result["updated"] == 0
            assert len(result["errors"]) == 0

            # Проверяем, что метаданные созданы
            meta_path = os.path.join(temp_dir, "newclient.json")
            assert os.path.exists(meta_path)
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            assert meta["name"] == "newclient"
            assert meta["pubkey"] == "new_pubkey"
            assert meta["preshared_key"] == "new_psk"
            assert meta["allowed_ips"] == "10.10.0.5/32"
            assert meta["synced_from_config"] is True

    def test_sync_from_single_config_update_existing(self, wg_manager, temp_dir):
        """Тест: синхронизация обновляет существующего клиента."""
        # Создаём существующего клиента
        meta_path = os.path.join(temp_dir, "existing.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "name": "existing",
                    "pubkey": "old_pubkey",
                    "client_ip": "10.10.0.2/24",
                },
                f,
            )

        config_path = os.path.join(temp_dir, "test.conf")
        config_content = """# BEGIN_PEER existing
[Peer]
PublicKey = new_pubkey
AllowedIPs = 10.10.0.2/32
PresharedKey = new_psk
# END_PEER existing
"""
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        result = wg_manager._sync_from_single_config(config_path)

        assert result["created"] == 0
        assert result["updated"] == 1
        assert len(result["errors"]) == 0

        # Проверяем, что метаданные обновлены
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        assert meta["pubkey"] == "new_pubkey"
        assert meta["preshared_key"] == "new_psk"
        assert meta["synced_from_config"] is True

    def test_sync_from_single_config_missing_pubkey(self, wg_manager, temp_dir):
        """Тест: синхронизация обрабатывает клиента без PublicKey."""
        config_path = os.path.join(temp_dir, "test.conf")
        config_content = """# BEGIN_PEER invalid
[Peer]
AllowedIPs = 10.10.0.2/32
# END_PEER invalid
"""
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        result = wg_manager._sync_from_single_config(config_path)

        assert result["created"] == 0
        assert result["updated"] == 0
        assert len(result["errors"]) == 1
        assert "missing PublicKey" in result["errors"][0]

    def test_sync_from_single_config_file_not_found(self, wg_manager):
        """Тест: синхронизация несуществующего файла вызывает ошибку."""
        with pytest.raises(WGManagerError, match="Config file not found"):
            wg_manager._sync_from_single_config("/nonexistent/path.conf")

    def test_sync_from_config_dir_single_file(self, wg_manager, temp_dir):
        """Тест: синхронизация директории с одним конфигом."""
        config_dir = os.path.join(temp_dir, "configs")
        os.makedirs(config_dir)

        config_path = os.path.join(config_dir, "wg0.conf")
        config_content = """# BEGIN_PEER client1
[Peer]
PublicKey = pubkey1
AllowedIPs = 10.10.0.2/32
# END_PEER client1
"""
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        with patch.object(wg_manager, "_next_free_ip") as mock_next_ip:
            mock_next_ip.return_value = "10.10.0.2/24"
            wg_manager.wg_config_dir = config_dir

            result = wg_manager.sync_from_config_dir()

            assert result["created"] == 1
            assert result["updated"] == 0
            assert result["files_processed"] == 1
            assert len(result["errors"]) == 0

    def test_sync_from_config_dir_multiple_files(self, wg_manager, temp_dir):
        """Тест: синхронизация директории с несколькими конфигами."""
        config_dir = os.path.join(temp_dir, "configs")
        os.makedirs(config_dir)

        # Создаём два конфига
        config1_path = os.path.join(config_dir, "wg0.conf")
        with open(config1_path, "w", encoding="utf-8") as f:
            f.write("""# BEGIN_PEER client1
[Peer]
PublicKey = pubkey1
AllowedIPs = 10.10.0.2/32
# END_PEER client1
""")

        config2_path = os.path.join(config_dir, "wg1.conf")
        with open(config2_path, "w", encoding="utf-8") as f:
            f.write("""# BEGIN_PEER client2
[Peer]
PublicKey = pubkey2
AllowedIPs = 10.10.0.3/32
# END_PEER client2
""")

        with patch.object(wg_manager, "_next_free_ip") as mock_next_ip:
            mock_next_ip.return_value = "10.10.0.2/24"
            wg_manager.wg_config_dir = config_dir

            result = wg_manager.sync_from_config_dir()

            assert result["created"] == 2
            assert result["updated"] == 0
            assert result["files_processed"] == 2
            assert len(result["errors"]) == 0

    def test_sync_from_config_dir_no_conf_files(self, wg_manager, temp_dir):
        """Тест: синхронизация директории без .conf файлов."""
        config_dir = os.path.join(temp_dir, "configs")
        os.makedirs(config_dir)

        # Создаём файл не .conf
        with open(os.path.join(config_dir, "readme.txt"), "w", encoding="utf-8") as f:
            f.write("test")

        wg_manager.wg_config_dir = config_dir

        result = wg_manager.sync_from_config_dir()

        assert result["created"] == 0
        assert result["updated"] == 0
        assert result["files_processed"] == 0
        assert len(result["errors"]) > 0
        assert "No .conf files found" in result["errors"][0]

    def test_sync_from_config_dir_directory_not_found(self, wg_manager):
        """Тест: синхронизация несуществующей директории вызывает ошибку."""
        wg_manager.wg_config_dir = "/nonexistent/directory"
        with pytest.raises(WGManagerError, match="Config directory not found"):
            wg_manager.sync_from_config_dir()

    def test_sync_from_config_dir_not_a_directory(self, wg_manager, temp_dir):
        """Тест: синхронизация файла вместо директории вызывает ошибку."""
        file_path = os.path.join(temp_dir, "not_a_dir")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("test")

        wg_manager.wg_config_dir = file_path
        with pytest.raises(WGManagerError, match="Path is not a directory"):
            wg_manager.sync_from_config_dir()

    def test_sync_from_config_dir_with_errors(self, wg_manager, temp_dir):
        """Тест: синхронизация директории с ошибками в одном из файлов."""
        config_dir = os.path.join(temp_dir, "configs")
        os.makedirs(config_dir)

        # Создаём валидный конфиг
        config1_path = os.path.join(config_dir, "wg0.conf")
        with open(config1_path, "w", encoding="utf-8") as f:
            f.write("""# BEGIN_PEER client1
[Peer]
PublicKey = pubkey1
AllowedIPs = 10.10.0.2/32
# END_PEER client1
""")

        # Создаём конфиг с ошибкой (нет PublicKey)
        config2_path = os.path.join(config_dir, "wg1.conf")
        with open(config2_path, "w", encoding="utf-8") as f:
            f.write("""# BEGIN_PEER client2
[Peer]
AllowedIPs = 10.10.0.3/32
# END_PEER client2
""")

        with patch.object(wg_manager, "_next_free_ip") as mock_next_ip:
            mock_next_ip.return_value = "10.10.0.2/24"
            wg_manager.wg_config_dir = config_dir

            result = wg_manager.sync_from_config_dir()

            assert result["created"] == 1  # client1 создан
            assert result["updated"] == 0
            assert result["files_processed"] == 2
            assert len(result["errors"]) == 1
            assert "missing PublicKey" in result["errors"][0]

