"""Локальное управление client keys, IP и файлами (.conf / .json)."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from config import BotConfig

NAME_PATTERN = re.compile(r"^[a-z0-9_-]+$")


class ClientManagerError(Exception):
    """Ошибка client_manager."""


@dataclass
class ClientRecord:
    name: str
    pubkey: str
    client_ip: str
    conf_path: str
    client_ip_v6: Optional[str] = None
    created_at: Optional[str] = None


class ClientManager:
    """Keygen, IP allocation, client conf и файлы в CLIENT_DIR."""

    def __init__(self, cfg: BotConfig, logger: Optional[logging.Logger] = None):
        self.cfg = cfg
        self.client_dir = cfg.client_dir
        self.wg_subnet = ipaddress.ip_network(cfg.wg_subnet)
        self.wg_subnet_v6 = (
            ipaddress.ip_network(cfg.wg_subnet_v6) if cfg.wg_subnet_v6 else None
        )
        self.logger = logger or logging.getLogger("client_manager")

        os.makedirs(self.client_dir, exist_ok=True)
        self._check_client_dir()

    def _check_client_dir(self) -> None:
        uid = os.getuid()
        st = os.stat(self.client_dir)
        if st.st_uid != uid:
            raise ClientManagerError(f"CLIENT_DIR must be owned by UID {uid}")
        if st.st_mode & 0o077:
            raise ClientManagerError(
                "CLIENT_DIR must not be group/other writable/readable"
            )

    @staticmethod
    def validate_name(name: str) -> None:
        if not name or not NAME_PATTERN.match(name.lower()):
            raise ClientManagerError("Invalid client name")

    def name_exists(self, name: str) -> bool:
        return os.path.exists(self._meta_path(name)) or os.path.exists(
            self._conf_path(name)
        )

    def generate_keypair(self) -> Tuple[str, str]:
        """wg genkey / wg pubkey без sudo."""
        try:
            priv = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True,
                env={"PATH": "/usr/bin:/bin"},
            ).stdout.strip()
            pub = subprocess.run(
                ["wg", "pubkey"],
                input=priv + "\n",
                capture_output=True,
                text=True,
                check=True,
                env={"PATH": "/usr/bin:/bin"},
            ).stdout.strip()
        except subprocess.CalledProcessError as e:
            raise ClientManagerError("Failed to generate WireGuard keypair") from e
        self.logger.debug("Generated keypair for new client")
        return priv, pub

    def list_used_ipv4_hosts(self) -> Set[str]:
        used: Set[str] = set()
        if not os.path.isdir(self.client_dir):
            return used
        for fn in os.listdir(self.client_dir):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.client_dir, fn), "r", encoding="utf-8") as f:
                    meta = json.load(f)
                ip = meta.get("client_ip")
                if ip:
                    used.add(str(ip).split("/")[0])
            except (OSError, json.JSONDecodeError):
                continue
        return used

    def allocate_ips(self, extra_used: Optional[Set[str]] = None) -> Tuple[str, Optional[str]]:
        """Выделяет пару IPv4 + IPv6 (если настроено) с общим host-id."""
        used = self.list_used_ipv4_hosts()
        if extra_used:
            used |= {h.split("/")[0] for h in extra_used}

        for ip in self.wg_subnet.hosts():
            host = str(ip)
            if host in used:
                continue
            ipv4 = f"{host}/{self.wg_subnet.prefixlen}"
            ipv6 = None
            if self.wg_subnet_v6:
                # fd66:66::N/128 где N = последний октет IPv4
                last = int(host.split(".")[-1])
                v6 = ipaddress.ip_address(
                    int(self.wg_subnet_v6.network_address) + last
                )
                if v6 not in self.wg_subnet_v6:
                    continue
                ipv6 = f"{v6}/{128}"
            self.logger.debug("Allocated IPs: v4=%s v6=%s", ipv4, ipv6)
            return ipv4, ipv6

        raise ClientManagerError("No free IPs available in subnet")

    def build_client_conf(
        self,
        private_key: str,
        client_ip: str,
        client_ip_v6: Optional[str] = None,
    ) -> str:
        cfg = self.cfg
        if not cfg.server_public_key:
            raise ClientManagerError("SERVER_PUBLIC_KEY not configured")
        endpoint = cfg.client_endpoint()
        if not endpoint:
            raise ClientManagerError("SERVER_ENDPOINT or SERVER_IP not configured")

        addresses = client_ip
        if client_ip_v6:
            addresses = f"{client_ip}, {client_ip_v6}"

        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {addresses}",
            f"DNS = {cfg.wg_dns}",
            f"MTU = {cfg.wg_mtu}",
            "",
            "[Peer]",
            f"PublicKey = {cfg.server_public_key}",
            f"AllowedIPs = {cfg.client_allowed_ips}",
            f"Endpoint = {endpoint}",
            f"PersistentKeepalive = {cfg.persistent_keepalive}",
            "",
        ]
        return "\n".join(lines)

    def save_client(
        self, name: str, pubkey: str, client_ip: str, conf_text: str, client_ip_v6: Optional[str] = None
    ) -> ClientRecord:
        self.validate_name(name)
        if self.name_exists(name):
            raise ClientManagerError("Client with that name already exists")

        conf_path = self._conf_path(name)
        meta_path = self._meta_path(name)
        created_at = datetime.now(timezone.utc).isoformat()

        meta = {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pubkey,
            "conf_path": conf_path,
            "created_at": created_at,
        }
        if client_ip_v6:
            meta["client_ip_v6"] = client_ip_v6

        self._atomic_write(conf_path, conf_text)
        self._atomic_write(meta_path, json.dumps(meta, indent=2))

        return ClientRecord(
            name=name,
            pubkey=pubkey,
            client_ip=client_ip,
            conf_path=conf_path,
            client_ip_v6=client_ip_v6,
            created_at=created_at,
        )

    def load_client(self, name: str) -> ClientRecord:
        meta_path = self._meta_path(name)
        if not os.path.exists(meta_path):
            raise ClientManagerError("Client not found")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return ClientRecord(
            name=meta.get("name", name),
            pubkey=meta.get("pubkey", ""),
            client_ip=meta.get("client_ip", ""),
            conf_path=meta.get("conf_path", self._conf_path(name)),
            client_ip_v6=meta.get("client_ip_v6"),
            created_at=meta.get("created_at"),
        )

    def read_conf(self, name: str) -> str:
        record = self.load_client(name)
        with open(record.conf_path, "r", encoding="utf-8") as f:
            return f.read()

    def update_client_after_rotate(
        self, name: str, new_pubkey: str, conf_text: str
    ) -> ClientRecord:
        record = self.load_client(name)
        self._atomic_write(record.conf_path, conf_text)
        meta_path = self._meta_path(name)
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["pubkey"] = new_pubkey
        self._atomic_write(meta_path, json.dumps(meta, indent=2))
        return ClientRecord(
            name=record.name,
            pubkey=new_pubkey,
            client_ip=record.client_ip,
            conf_path=record.conf_path,
            client_ip_v6=record.client_ip_v6,
            created_at=record.created_at,
        )

    def remove_client_files(self, name: str) -> None:
        record = self.load_client(name)
        if record.conf_path and os.path.exists(record.conf_path):
            os.remove(record.conf_path)
        meta_path = self._meta_path(name)
        if os.path.exists(meta_path):
            os.remove(meta_path)

    def list_local_clients(self) -> List[ClientRecord]:
        clients: List[ClientRecord] = []
        if not os.path.isdir(self.client_dir):
            return clients
        for fn in os.listdir(self.client_dir):
            if not fn.endswith(".json"):
                continue
            name = fn[:-5]
            try:
                clients.append(self.load_client(name))
            except (ClientManagerError, json.JSONDecodeError):
                continue
        return clients

    def _meta_path(self, name: str) -> str:
        return os.path.join(self.client_dir, f"{name}.json")

    def _conf_path(self, name: str) -> str:
        return os.path.join(self.client_dir, f"{name}.conf")

    def _atomic_write(self, path: str, data: str, mode: int = 0o600) -> None:
        if os.path.exists(path) and os.path.islink(path):
            raise ClientManagerError("Refusing to overwrite symlink")
        dir_name = os.path.dirname(path) or "."
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
