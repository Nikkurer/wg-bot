# wg_manager.py
import os
import subprocess
import ipaddress
import json
import tempfile
import logging

class WGManagerError(Exception):
    def __init__(self, message, logger=None, level="error", **kwargs):
        super().__init__(message)
        self._extra = kwargs  # любые дополнительные данные (например stderr)
        if logger:
            log_func = getattr(logger, level, logger.error)
            log_func(f"[WGManagerError] {message}")

class WGManager:
    def __init__(self, wg_iface, client_dir, wg_subnet, server_public_key=None, logger=None):
        self.wg_iface = wg_iface
        self.client_dir = client_dir
        self.wg_subnet = ipaddress.ip_network(wg_subnet)
        self.server_public_key = server_public_key

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
            raise WGManagerError("CLIENT_DIR must not be group/other writable")
        self.logger.debug(f"CLIENT_DIR permissions OK: {self.client_dir}")

    # --- helper subprocess wrapper (avoid logging secrets) ---
    def _run(self, cmd, input_data=None, check=True):
        """Run subprocess and return stdout (text). Raises WGManagerError on failure."""
        try:
            proc = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                check=check,
                text=True,
                env={"PATH": "/usr/bin:/bin"}
            )
            self.logger.debug(f"Command succeeded: {' '.join(cmd)}")
            return proc.stdout.strip()
        except subprocess.CalledProcessError as e:
            safe_err = "Что-то пошло не так. Напиши админу" if e.stderr else "Упс. Не понял что произошло - напиши админу."
            ex = WGManagerError(f"Command failed: {' '.join(cmd)}; exit={e.returncode}; stderr={safe_err}")
            ex._full_stderr = e.stderr
            self.logger.error(f"Command failed: {' '.join(cmd)}; exit={e.returncode}")
            self.logger.debug(f"STDERR:\ {ex._full_stderr}")
            raise ex

    # --- status ---
    def status(self):
        # Return sanitized wg show output
        out = self._run(["sudo", "wg", "show", self.wg_iface, "dump"])
        # The dump contains keys and such — sanitize private-like fields:
        # wg dump columns: interface, private key, public key, listen port, fwmark, peer public key, preshared key, endpoint, allowed ips, latest handshake, rx_bytes, tx_bytes
        # We will hide columns that look like keys by replacing long base64-like strings with "<REDACTED>"
        sanitized_lines = []
        for line in out.splitlines():
            cols = line.split("\t")
            safe_cols = []
            for c in cols:
                if len(c) > 40 and all(ch.isalnum() or ch in "+/=" for ch in c[:20]):
                    safe_cols.append("<REDACTED>")
                else:
                    safe_cols.append(c)
            sanitized_lines.append("\t".join(safe_cols))
        self.logger.debug(f"Status fetched: {len(sanitized_lines)} lines")
        return "\n".join(sanitized_lines) if sanitized_lines else "(no output)"

    # --- key generation ---
    def _gen_keypair(self):
        priv = self._run(["sudo", "wg", "genkey"])
        proc = subprocess.run(["sudo", "wg", "pubkey"], input=priv + "\n", capture_output=True, text=True, check=True)
        pub = proc.stdout.strip()
        self.logger.debug("Generated keypair for new client")
        return priv.strip(), pub.strip()

    # --- helper: atomic write ---
    def _atomic_write(self, path, data, mode=0o600):
        """Атомарная запись файла

        Args:
            path (str): Путь до файлв
            data (str): Данные для записи
            mode (int, optional): Права на файл. По умоланию 0o600.

        Raises:
            WGManagerError: Ошибка при записи файла
        """
        if os.path.exists(path) and os.path.islink(path):
            raise WGManagerError("Refusing to overwrite symlink")
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)
        fd, tmp_path = tempfile.mkstemp(prefix=base_name, dir=dir_name, text=True)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(data)
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    # --- find next free IP ---
    def _list_used_ips(self):
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
        used = self._list_used_ips()
        # skip network address and server address; start from .2
        # iterate hosts in wg_subnet (exclude network and broadcast)
        for ip in self.wg_subnet.hosts():
            s = str(ip)
            if s not in used:
                self.logger.debug(f"Next free IP: {s}")
                return s + '/' + str(self.wg_subnet.prefixlen)
        raise WGManagerError("No free IPs available in subnet")

    # --- add client ---
    def add_client(self, name, allowed_ips=None):
        if not name or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for ch in name.lower()):
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
            self._run(["sudo", "wg", "set", self.wg_iface, "peer", pub, "allowed-ips", client_ip.split("/")[0] + "/32"])
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
                    self._run(["sudo", "wg", "set", self.wg_iface, "peer", pub, "remove"])
                    self.logger.info(f"Rollback peer {name} due to write failure")
                except Exception:
                    pass
            raise WGManagerError(f"Failed to add client: {e}")

        return {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pub,
            "conf_path": conf_path,
            "client_conf": client_conf_text
        }

    # --- remove client ---
    def remove_client(self, name):
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
        """Возвращает статистику для клиента по имени"""
        meta_path = os.path.join(self.client_dir, f"{name}.json")
        if not os.path.exists(meta_path):
            raise WGManagerError("Client not found")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        pub = meta.get("pubkey")
        if not pub:
            raise WGManagerError("No pubkey in client metadata")

        dump = self._run(["sudo", "wg", "show", self.wg_iface, "dump"])
        for line in dump.splitlines():
            cols = line.split("\t")
            if len(cols) >= 12 and cols[1] != pub and cols[5] == pub:  # peer pubkey в 6-й колонке
                return {
                    "pubkey": cols[5],
                    "endpoint": cols[7] or "(нет)",
                    "allowed_ips": cols[8],
                    "latest_handshake": cols[9],
                    "rx_bytes": cols[10],
                    "tx_bytes": cols[11],
                }
        raise WGManagerError("Peer not found in wg dump")


    # --- list clients ---
    def list_clients(self):
        clients = []
        for fn in os.listdir(self.client_dir):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(self.client_dir, fn), "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    clients.append({
                        "name": meta.get("name"),
                        "ip": meta.get("client_ip"),
                        "pubkey": meta.get("pubkey"),
                    })
                except Exception as e:
                    self.logger.warning(f"Failed to read client file {fn}: {e}")
                    continue
        return clients
