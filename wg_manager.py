# wg_manager.py
import ipaddress
import json
import logging
import os
import subprocess
import tempfile


class WGManagerError(Exception):
    """Исключение для ошибок управления WireGuard.

    Используется для обработки ошибок при работе с WireGuard интерфейсом,
    клиентами и конфигурацией.

    Attributes:
        _extra (dict): Дополнительные данные об ошибке (например, stderr).
    """

    def __init__(self, message, logger=None, level="error", **kwargs):
        """Инициализирует исключение.

        Args:
            message (str): Сообщение об ошибке.
            logger (logging.Logger, optional): Логгер для записи ошибки.
            level (str, optional): Уровень логирования. По умолчанию "error".
            **kwargs: Дополнительные данные об ошибке.
        """
        super().__init__(message)
        self._extra = kwargs  # любые дополнительные данные (например stderr)
        if logger:
            log_func = getattr(logger, level, logger.error)
            log_func(f"[WGManagerError] {message}")


class WGManager:
    """Менеджер для управления WireGuard интерфейсом и клиентами.

    Предоставляет функциональность для создания, удаления и управления
    клиентами WireGuard, а также для получения статистики и статуса.
    """

    def __init__(
        self, wg_iface, client_dir, wg_subnet, server_public_key=None, wg_config_dir=None, logger=None
    ):
        """Инициализирует менеджер WireGuard.

        Args:
            wg_iface (str): Имя интерфейса WireGuard (например, "wg0").
            client_dir (str): Путь к директории для хранения конфигураций клиентов.
            wg_subnet (str): Подсеть WireGuard в формате CIDR (например, "10.10.0.0/24").
            server_public_key (str, optional): Публичный ключ сервера для клиентских конфигов.
            wg_config_dir (str, optional): Путь к директории с конфигами WireGuard для синхронизации.
            logger (logging.Logger, optional): Логгер для записи событий.

        Raises:
            WGManagerError: Если директория клиентов не принадлежит текущему пользователю
                или имеет небезопасные права доступа.
        """
        self.wg_iface = wg_iface
        self.client_dir = client_dir
        self.wg_subnet = ipaddress.ip_network(wg_subnet)
        self.server_public_key = server_public_key
        self.wg_config_dir = wg_config_dir

        # --- logger setup ---
        self.logger = logger or logging.getLogger("wg_manager")
        self.logger.debug("Initializing WGManager...")

        uid = os.getuid()
        # Проверка каталога
        os.makedirs(self.client_dir, exist_ok=True)
        st = os.stat(self.client_dir)
        if st.st_uid != uid:
            raise WGManagerError(f"CLIENT_DIR must be owned by UID {uid}")
        if st.st_mode & 0o077:
            raise WGManagerError(
                "CLIENT_DIR must not be group/other writable/ readable"
            )
        self.logger.debug(f"CLIENT_DIR permissions OK: {self.client_dir}")

    # --- helper subprocess wrapper (avoid logging secrets) ---
    def _run(self, cmd, input_data=None, check=True):
        """Выполняет команду через subprocess и возвращает stdout.

        Обёртка для subprocess.run с обработкой ошибок и логированием.
        Скрывает секретные данные в логах.

        Args:
            cmd (list): Список аргументов команды (например, ["wg", "show", "wg0"]).
            input_data (str, optional): Данные для передачи в stdin команды.
            check (bool, optional): Если True, вызывает исключение при ненулевом коде возврата.
                По умолчанию True.

        Returns:
            str: Вывод команды (stdout) с удалёнными пробелами в начале и конце.

        Raises:
            WGManagerError: Если команда завершилась с ошибкой (при check=True).
        """
        try:
            proc = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                check=check,
                text=True,
                env={"PATH": "/usr/bin:/bin"},
            )
            self.logger.debug(f"Command succeeded: {' '.join(cmd)}")
            return proc.stdout.strip()
        except subprocess.CalledProcessError as e:
            safe_err = (
                "Что-то пошло не так. Напиши админу"
                if e.stderr
                else "Упс. Не понял что произошло - напиши админу."
            )
            ex = WGManagerError(
                f"Command failed: {' '.join(cmd)}; exit={e.returncode}; stderr={safe_err}"
            )
            ex._full_stderr = e.stderr
            self.logger.error(f"Command failed: {' '.join(cmd)}; exit={e.returncode}")
            self.logger.debug(f"STDERR: {ex._full_stderr}")
            raise ex

    # --- status ---
    def status(self):
        """Возвращает санитизированный вывод статуса WireGuard.

        Выполняет `wg show <interface> dump` и скрывает секретные данные
        (приватные ключи и preshared keys), оставляя публичные ключи
        для идентификации пиров.

        Returns:
            str: Многострочный вывод статуса с скрытыми секретами.
                Формат: первая строка - интерфейс, остальные - пиры.
        """
        out = self._run(["sudo", "wg", "show", self.wg_iface, "dump"])
        # The dump contains keys and such — sanitize private-like fields:
        # wg dump format:
        #   First line (interface): private_key, public_key, listen_port, fwmark
        #   Other lines (peers): peer_public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx_bytes, tx_bytes, keepalive
        # We hide: private_key (interface, col 0), preshared_key (peers, col 1)
        # We keep: public_key (interface, col 1), peer_public_key (peers, col 0) - needed for identification
        sanitized_lines = []
        for idx, line in enumerate(out.splitlines()):
            cols = line.split("\t")
            safe_cols = []
            if idx == 0:
                # First line: interface - hide private_key (col 0)
                for i, c in enumerate(cols):
                    if i == 0:  # private_key
                        safe_cols.append("<REDACTED>")
                    else:
                        safe_cols.append(c)
            else:
                # Peer lines - hide preshared_key (col 1), keep peer_public_key (col 0)
                for i, c in enumerate(cols):
                    if i == 1:  # preshared_key
                        safe_cols.append("<REDACTED>")
                    else:
                        safe_cols.append(c)
            sanitized_lines.append("\t".join(safe_cols))
        self.logger.debug(f"Status fetched: {len(sanitized_lines)} lines")
        return "\n".join(sanitized_lines) if sanitized_lines else "(no output)"

    # --- key generation ---
    def _gen_keypair(self):
        """Генерирует пару ключей WireGuard (приватный и публичный).

        Использует команды `wg genkey` и `wg pubkey` для генерации ключей.

        Returns:
            tuple[str, str]: Кортеж (приватный_ключ, публичный_ключ).
        """
        priv = self._run(["sudo", "wg", "genkey"])
        proc = subprocess.run(
            ["sudo", "wg", "pubkey"],
            input=priv + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        pub = proc.stdout.strip()
        self.logger.debug("Generated keypair for new client")
        return priv.strip(), pub.strip()

    # --- helper: atomic write ---
    def _atomic_write(self, path, data, mode=0o600):
        """Атомарно записывает данные в файл.

        Создаёт временный файл, записывает данные, устанавливает права доступа
        и затем атомарно заменяет целевой файл. Это предотвращает повреждение
        данных при сбоях во время записи.

        Args:
            path (str): Путь к целевому файлу.
            data (str): Данные для записи в файл.
            mode (int, optional): Права доступа к файлу в восьмеричном формате.
                По умолчанию 0o600 (rw-------).

        Raises:
            WGManagerError: Если целевой путь является символической ссылкой
                или произошла ошибка при записи.
        """
        if os.path.exists(path) and os.path.islink(path):
            raise WGManagerError("Refusing to overwrite symlink")
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)
        fd, tmp_path = tempfile.mkstemp(prefix=base_name, dir=dir_name, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    # --- find next free IP ---
    def _list_used_ips(self):
        """Возвращает множество используемых IP-адресов в подсети.

        Сканирует метаданные клиентов и вывод `wg show` для определения
        всех занятых IP-адресов в подсети WireGuard.

        Returns:
            set[str]: Множество используемых IP-адресов (без маски подсети).
        """
        used = set()
        # scan client metadata files
        for fn in os.listdir(self.client_dir):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(self.client_dir, fn), "r") as f:
                        j = json.load(f)
                    ip = j.get("client_ip")
                    if ip:
                        used.add(ip.split("/")[0])
                except Exception:
                    continue
        # also parse 'wg show' for allowed-ips
        try:
            dump = self._run(["sudo", "wg", "show", self.wg_iface, "dump"])
            for line in dump.splitlines():
                cols = line.split("\t")
                if len(cols) >= 9:
                    allowed = cols[8]
                    for a in allowed.split(","):
                        a = a.strip()
                        if a:
                            used.add(a.split("/")[0])
        except WGManagerError:
            pass
        self.logger.debug(f"Used IPs: {used}")
        return used

    def _next_free_ip(self):
        """Находит следующий свободный IP-адрес в подсети WireGuard.

        Итерируется по хостам в подсети (исключая сетевой и broadcast адреса)
        и возвращает первый свободный IP.

        Returns:
            str: Свободный IP-адрес с маской подсети (например, "10.10.0.2/24").

        Raises:
            WGManagerError: Если в подсети нет свободных IP-адресов.
        """
        used = self._list_used_ips()
        # skip network address and server address; start from .2
        # iterate hosts in wg_subnet (exclude network and broadcast)
        for ip in self.wg_subnet.hosts():
            s = str(ip)
            if s not in used:
                self.logger.debug(f"Next free IP: {s}")
                return s + "/" + str(self.wg_subnet.prefixlen)
        raise WGManagerError("No free IPs available in subnet")

    def add_client(self, name, allowed_ips=None):
        """Добавляет нового клиента WireGuard.

        Создаёт пару ключей, находит свободный IP, добавляет пира в интерфейс
        и создаёт конфигурационные файлы (.conf и .json).

        Args:
            name (str): Имя клиента. Должно содержать только буквы, цифры,
                дефисы и подчёркивания.
            allowed_ips (str, optional): Разрешённые IP-адреса для клиента.
                По умолчанию "0.0.0.0/0" (весь трафик).

        Returns:
            dict: Словарь с информацией о созданном клиенте:
                - name (str): Имя клиента
                - client_ip (str): IP-адрес клиента в подсети
                - pubkey (str): Публичный ключ клиента
                - conf_path (str): Путь к файлу конфигурации
                - client_conf (str): Содержимое конфигурационного файла

        Raises:
            WGManagerError: Если имя клиента невалидно, клиент уже существует,
                нет свободных IP-адресов или произошла ошибка при создании.
        """
        if not name or any(
            ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in name.lower()
        ):
            raise WGManagerError("Invalid client name")
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        conf_path = os.path.join(self.client_dir, f"{name}.conf")
        if os.path.exists(meta_path) or os.path.exists(conf_path):
            raise WGManagerError("Client with that name already exists")

        priv, pub = self._gen_keypair()
        client_ip = self._next_free_ip()
        if not allowed_ips:
            allowed_ips = "0.0.0.0/0"

        added_peer = False
        try:
            # добавляем пир в интерфейс
            self._run(
                [
                    "sudo",
                    "wg",
                    "set",
                    self.wg_iface,
                    "peer",
                    pub,
                    "allowed-ips",
                    client_ip.split("/")[0] + "/32",
                ]
            )
            added_peer = True
            self.logger.info(f"Added peer {name} with IP {client_ip}")

            server_pub = self.server_public_key or "<SERVER_PUBLIC_KEY>"
            client_conf = [
                "[Interface]",
                f"PrivateKey = {priv}",
                f"Address = {client_ip}",
                "DNS = 1.1.1.1",
                "",
                "[Peer]",
                f"PublicKey = {server_pub}",
                f"AllowedIPs = {allowed_ips}",
            ]
            client_conf_text = "\n".join(client_conf)

            # atomic write файлов
            self._atomic_write(conf_path, client_conf_text, mode=0o600)
            meta = {
                "name": name,
                "client_ip": client_ip,
                "pubkey": pub,
                "conf_path": conf_path,
            }
            self._atomic_write(meta_path, json.dumps(meta, indent=2), mode=0o600)
            self.logger.debug(f"Client files written for {name}")
        except Exception as e:
            if added_peer:
                # rollback peer
                try:
                    self._run(
                        ["sudo", "wg", "set", self.wg_iface, "peer", pub, "remove"]
                    )
                    self.logger.info(f"Rollback peer {name} due to write failure")
                except Exception:
                    pass
            raise WGManagerError(f"Failed to add client: {e}")

        return {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pub,
            "conf_path": conf_path,
            "client_conf": client_conf_text,
        }

    def remove_client(self, name):
        """Удаляет клиента WireGuard.

        Удаляет пира из интерфейса WireGuard и удаляет конфигурационные файлы.

        Args:
            name (str): Имя клиента для удаления.

        Returns:
            bool: True при успешном удалении.

        Raises:
            WGManagerError: Если клиент не найден или произошла ошибка
                при удалении пира или файлов.
        """
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        if not os.path.exists(meta_path):
            raise WGManagerError("Client not found")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        pub = meta.get("pubkey")
        conf_path = meta.get("conf_path")

        try:
            self._run(["sudo", "wg", "set", self.wg_iface, "peer", pub, "remove"])
            self.logger.info(f"Removed peer {name}")
        except WGManagerError as e:
            self.logger.error(f"Failed to remove peer {name}: {e}")
            raise WGManagerError(e)

        # удалить файлы
        try:
            if conf_path and os.path.exists(conf_path):
                os.remove(conf_path)
            os.remove(meta_path)
            self.logger.debug(f"Client files removed for {name}")
        except Exception as e:
            self.logger.error(f"Failed to remove client files for {name}: {e}")
            raise WGManagerError(f"Failed to remove client files: {e}")

        return True

    def peer_stats(self, name):
        """Возвращает статистику подключения для клиента.

        Получает статистику пира из вывода `wg show dump` по публичному ключу
        клиента.

        Args:
            name (str): Имя клиента.

        Returns:
            dict: Словарь со статистикой пира:
                - pubkey (str): Публичный ключ пира
                - endpoint (str): Адрес endpoint или "(нет)"
                - allowed_ips (str): Разрешённые IP-адреса
                - latest_handshake (str): Timestamp последнего handshake
                - rx_bytes (str): Количество полученных байт
                - tx_bytes (str): Количество отправленных байт

        Raises:
            WGManagerError: Если клиент не найден, нет публичного ключа
                в метаданных, вывод wg dump пуст или пир не найден в dump.
        """
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        if not os.path.exists(meta_path):
            raise WGManagerError("Client not found")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        pub = meta.get("pubkey")
        if not pub:
            raise WGManagerError("No pubkey in client metadata")

        dump = self._run(["sudo", "wg", "show", self.wg_iface, "dump"])
        # Формат wg dump:
        # Первая строка (интерфейс): private_key, public_key, listen_port, fwmark
        # Остальные строки (пиры): peer_public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx_bytes, tx_bytes, keepalive
        # Колонки пира: 0, 1, 2, 3, 4, 5, 6, 7
        lines = dump.splitlines()
        if not lines:
            raise WGManagerError("Empty wg dump output")

        # Пропускаем первую строку (интерфейс) и ищем пира по публичному ключу в колонке 0
        for line in lines[1:]:
            cols = line.split("\t")
            if len(cols) >= 8 and cols[0] == pub:
                self.logger.debug(f"Found peer {name} with pubkey {pub[:8]}...")
                return {
                    "pubkey": cols[0],
                    "endpoint": cols[2] or "(нет)",
                    "allowed_ips": cols[3],
                    "latest_handshake": cols[4],
                    "rx_bytes": cols[5],
                    "tx_bytes": cols[6],
                }

        self.logger.warning(
            f"Peer {name} with pubkey {pub[:8]}... not found in wg dump (checked {len(lines) - 1} peer lines)"
        )
        raise WGManagerError("Peer not found in wg dump")

    def list_clients(self):
        """Возвращает список всех клиентов WireGuard.

        Сканирует директорию клиентов и загружает метаданные из JSON-файлов.

        Returns:
            list[dict]: Список словарей с информацией о клиентах:
                - name (str): Имя клиента
                - ip (str): IP-адрес клиента в подсети
                - pubkey (str): Публичный ключ клиента

        Raises:
            WGManagerError: Если невозможно получить доступ к директории клиентов.
        """
        clients = []
        try:
            files = os.listdir(self.client_dir)
            self.logger.debug(f"Scanning {self.client_dir}: found {len(files)} files")
            json_files = [f for f in files if f.endswith(".json")]
            self.logger.debug(f"Found {len(json_files)} JSON files: {json_files}")

            if not json_files:
                self.logger.info(f"No JSON files found in {self.client_dir}")
                return clients

            for fn in json_files:
                try:
                    file_path = os.path.join(self.client_dir, fn)
                    with open(file_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)

                    # Проверяем наличие обязательных полей
                    name = meta.get("name")
                    ip = meta.get("client_ip")
                    pubkey = meta.get("pubkey")

                    if not name or not ip or not pubkey:
                        self.logger.warning(
                            f"Client file {fn} missing required fields: name={name}, ip={ip}, pubkey={'present' if pubkey else 'missing'}"
                        )
                        continue

                    clients.append(
                        {
                            "name": name,
                            "ip": ip,
                            "pubkey": pubkey,
                        }
                    )
                    self.logger.debug(f"Successfully loaded client {name} from {fn}")
                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON in {fn}: {e}")
                    continue
                except Exception as e:
                    self.logger.error(
                        f"Failed to read client file {fn}: {e}", exc_info=True
                    )
                    continue

            self.logger.info(
                f"Loaded {len(clients)} clients from {len(json_files)} JSON files"
            )
        except OSError as e:
            self.logger.error(f"Cannot access client directory {self.client_dir}: {e}")
            raise WGManagerError(f"Cannot access client directory: {e}")

        return clients

    def sync_from_config_dir(self, config_dir=None):
        """Синхронизирует клиентов из всех конфигурационных файлов WireGuard в директории.

        Сканирует директорию с конфигами WireGuard и извлекает информацию о клиентах
        из всех .conf файлов. Для каждого найденного клиента обновляет или создаёт метаданные.

        Args:
            config_dir (str, optional): Путь к директории с конфигами WireGuard.
                Если не указан, используется self.wg_config_dir.

        Returns:
            dict: Словарь с результатами синхронизации:
                - created (int): Количество созданных клиентов
                - updated (int): Количество обновлённых клиентов
                - errors (list): Список ошибок при обработке клиентов
                - files_processed (int): Количество обработанных файлов

        Raises:
            WGManagerError: Если директория не найдена или произошла ошибка.
        """
        if config_dir is None:
            config_dir = self.wg_config_dir

        if not config_dir:
            raise WGManagerError("WG_CONFIG_DIR not configured")

        if not os.path.exists(config_dir):
            raise WGManagerError(f"Config directory not found: {config_dir}")

        if not os.path.isdir(config_dir):
            raise WGManagerError(f"Path is not a directory: {config_dir}")

        # Находим все .conf файлы в директории
        config_files = []
        try:
            for filename in os.listdir(config_dir):
                if filename.endswith(".conf"):
                    config_files.append(os.path.join(config_dir, filename))
        except OSError as e:
            raise WGManagerError(f"Cannot access config directory: {e}")

        if not config_files:
            self.logger.warning(f"No .conf files found in {config_dir}")
            return {
                "created": 0,
                "updated": 0,
                "errors": ["No .conf files found"],
                "files_processed": 0,
            }

        self.logger.info(f"Found {len(config_files)} config files to process")

        total_created = 0
        total_updated = 0
        all_errors = []
        files_processed = 0

        # Обрабатываем каждый конфиг
        for config_path in config_files:
            try:
                result = self._sync_from_single_config(config_path)
                total_created += result["created"]
                total_updated += result["updated"]
                all_errors.extend(result["errors"])
                files_processed += 1
            except Exception as e:
                error_msg = f"Failed to process {config_path}: {e}"
                all_errors.append(error_msg)
                self.logger.error(error_msg, exc_info=True)

        self.logger.info(
            f"Sync completed: {total_created} created, {total_updated} updated, "
            f"{len(all_errors)} errors, {files_processed} files processed"
        )

        return {
            "created": total_created,
            "updated": total_updated,
            "errors": all_errors,
            "files_processed": files_processed,
        }

    def _sync_from_single_config(self, config_path):
        """Синхронизирует клиентов из одного конфигурационного файла WireGuard.

        Args:
            config_path (str): Путь к конфигурационному файлу WireGuard.

        Returns:
            dict: Словарь с результатами синхронизации для одного файла.
        """
        if not os.path.exists(config_path):
            raise WGManagerError(f"Config file not found: {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_content = f.read()
        except Exception as e:
            raise WGManagerError(f"Failed to read config file: {e}")

        # Парсим секции клиентов
        clients_data = self._parse_config_peers(config_content)

        created = 0
        updated = 0
        errors = []

        for name, peer_data in clients_data.items():
            try:
                pubkey = peer_data.get("PublicKey", "").strip()
                allowed_ips = peer_data.get("AllowedIPs", "").strip()
                preshared_key = peer_data.get("PresharedKey", "").strip()

                if not pubkey:
                    errors.append(f"Client {name}: missing PublicKey")
                    continue

                # Извлекаем IP адрес из AllowedIPs (берём первый IP)
                client_ip = None
                if allowed_ips:
                    # AllowedIPs может содержать несколько IP через запятую
                    first_ip = allowed_ips.split(",")[0].strip()
                    # Если это IP с маской, убираем маску для определения адреса клиента
                    if "/" in first_ip:
                        ip_part = first_ip.split("/")[0]
                        # Проверяем, является ли это IP из нашей подсети
                        try:
                            ip_obj = ipaddress.ip_address(ip_part)
                            if ip_obj in self.wg_subnet:
                                client_ip = first_ip
                        except ValueError:
                            pass

                # Если IP не найден, пытаемся найти свободный
                if not client_ip:
                    try:
                        client_ip = self._next_free_ip()
                    except WGManagerError:
                        errors.append(f"Client {name}: no free IP available")
                        continue

                meta_path = os.path.join(self.client_dir, f"{name}.json")

                # Проверяем, существует ли клиент
                if os.path.exists(meta_path):
                    # Обновляем существующего клиента
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)

                    meta["pubkey"] = pubkey
                    if client_ip:
                        meta["client_ip"] = client_ip
                    if preshared_key:
                        meta["preshared_key"] = preshared_key
                    meta["allowed_ips"] = allowed_ips
                    meta["synced_from_config"] = True

                    self._atomic_write(
                        meta_path, json.dumps(meta, indent=2), mode=0o600
                    )
                    updated += 1
                    self.logger.info(f"Updated client {name} from config")
                else:
                    # Создаём нового клиента (без приватного ключа)
                    meta = {
                        "name": name,
                        "client_ip": client_ip,
                        "pubkey": pubkey,
                        "allowed_ips": allowed_ips,
                        "synced_from_config": True,
                    }
                    if preshared_key:
                        meta["preshared_key"] = preshared_key

                    self._atomic_write(
                        meta_path, json.dumps(meta, indent=2), mode=0o600
                    )
                    created += 1
                    self.logger.info(f"Created client {name} from config (no private key)")

            except Exception as e:
                error_msg = f"Client {name}: {e}"
                errors.append(error_msg)
                self.logger.error(error_msg, exc_info=True)

        self.logger.debug(
            f"File {config_path}: {created} created, {updated} updated, {len(errors)} errors"
        )

        return {
            "created": created,
            "updated": updated,
            "errors": errors,
        }

    def _parse_config_peers(self, config_content):
        """Парсит секции пиров из конфига WireGuard.

        Ищет секции между маркерами:
        # BEGIN_PEER <имя>
        ...
        # END_PEER <имя>

        Args:
            config_content (str): Содержимое конфигурационного файла.

        Returns:
            dict: Словарь с данными клиентов:
                {имя: {"PublicKey": "...", "AllowedIPs": "...", "PresharedKey": "..."}}
        """
        clients = {}
        lines = config_content.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Ищем начало секции клиента
            if line.startswith("# BEGIN_PEER"):
                # Извлекаем имя клиента
                parts = line.split(None, 2)
                if len(parts) < 3:
                    i += 1
                    continue

                client_name = parts[2].strip()
                if not client_name:
                    i += 1
                    continue

                # Ищем параметры внутри секции
                peer_data = {}
                i += 1

                while i < len(lines):
                    current_line = lines[i].strip()

                    # Проверяем конец секции
                    if current_line.startswith("# END_PEER"):
                        end_parts = current_line.split(None, 2)
                        if len(end_parts) >= 3 and end_parts[2].strip() == client_name:
                            clients[client_name] = peer_data
                            break

                    # Парсим параметры [Peer]
                    if current_line.startswith("[Peer]"):
                        i += 1
                        continue

                    # Парсим ключ=значение (формат: "PublicKey = ..." или "PublicKey=...")
                    if "=" in current_line and not current_line.startswith("#"):
                        key, value = current_line.split("=", 1)
                        key = key.strip()
                        value = value.strip()
                        # Поддерживаем оба формата: "PublicKey" и "PublicKey ="
                        if key in ["PublicKey", "AllowedIPs", "PresharedKey"]:
                            peer_data[key] = value

                    i += 1

            i += 1

        return clients
