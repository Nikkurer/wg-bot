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
from typing import List, Optional, Tuple

from config import BotConfig
from messages import CLIENT_ALREADY_EXISTS, CLIENT_NOT_FOUND, INVALID_CLIENT_NAME

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
    owner: Optional[int] = None


class ClientManager:
    """Keygen, IP allocation, client conf и файлы в CLIENT_DIR."""

    def __init__(
        self,
        cfg: BotConfig,
        logger: Optional[logging.Logger] = None,
        *,
        verify_dir: bool = True,
    ):
        self.cfg = cfg
        self.client_dir = cfg.client_dir
        self.wg_subnet = ipaddress.ip_network(cfg.wg_subnet)
        self.wg_subnet_v6 = (
            ipaddress.ip_network(cfg.wg_subnet_v6) if cfg.wg_subnet_v6 else None
        )
        self.logger = logger or logging.getLogger("client_manager")

        os.makedirs(self.client_dir, exist_ok=True)
        if verify_dir:
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
            raise ClientManagerError(INVALID_CLIENT_NAME)

    def name_exists(self, name: str) -> bool:
        self.validate_name(name)
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

    def parse_peer_ips(self, allowed_ips: List[str]) -> Tuple[str, Optional[str]]:
        """Разбирает allowed_ips peer-а из wg-admin на IPv4 и IPv6 для client conf."""
        client_ip: Optional[str] = None
        client_ip_v6: Optional[str] = None
        for cidr in allowed_ips:
            try:
                iface = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            if iface.version == 4 and client_ip is None:
                client_ip = cidr
            elif iface.version == 6 and client_ip_v6 is None:
                client_ip_v6 = cidr
        if not client_ip:
            raise ClientManagerError("Peer has no IPv4 in allowed_ips")
        return client_ip, client_ip_v6

    def derive_ipv6_from_ipv4(self, client_ip: str) -> Optional[str]:
        """Строит IPv6 клиента по последнему октету IPv4 (fd66:66::N/128)."""
        if not self.wg_subnet_v6:
            return None
        host = client_ip.split("/")[0]
        last = int(host.split(".")[-1])
        v6 = ipaddress.ip_address(int(self.wg_subnet_v6.network_address) + last)
        if v6 not in self.wg_subnet_v6:
            raise ClientManagerError(f"IPv6 {v6} is outside configured subnet")
        return f"{v6}/128"

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
        self,
        name: str,
        pubkey: str,
        client_ip: str,
        conf_text: str,
        client_ip_v6: Optional[str] = None,
        *,
        owner: int,
    ) -> ClientRecord:
        self.validate_name(name)
        if self.name_exists(name):
            raise ClientManagerError(CLIENT_ALREADY_EXISTS)

        conf_path = self._conf_path(name)
        meta_path = self._meta_path(name)
        created_at = datetime.now(timezone.utc).isoformat()

        meta = {
            "name": name,
            "client_ip": client_ip,
            "pubkey": pubkey,
            "conf_path": conf_path,
            "created_at": created_at,
            "owner": owner,
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
            owner=owner,
        )

    def load_client(self, name: str) -> ClientRecord:
        self.validate_name(name)
        meta_path = self._meta_path(name)
        if not os.path.exists(meta_path):
            raise ClientManagerError(CLIENT_NOT_FOUND)
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta_name = meta.get("name", name)
        if meta_name != name:
            self.validate_name(meta_name)
        conf_path = self._conf_path(name)
        owner = meta.get("owner")
        if owner is not None:
            owner = int(owner)
        return ClientRecord(
            name=name,
            pubkey=meta.get("pubkey", ""),
            client_ip=meta.get("client_ip", ""),
            conf_path=conf_path,
            client_ip_v6=meta.get("client_ip_v6"),
            created_at=meta.get("created_at"),
            owner=owner,
        )

    def read_conf(self, name: str) -> str:
        record = self.load_client(name)
        with open(record.conf_path, "r", encoding="utf-8") as f:
            return f.read()

    def update_client_after_rotate(
        self, name: str, new_pubkey: str, conf_text: str
    ) -> ClientRecord:
        self.validate_name(name)
        record = self.load_client(name)
        conf_path = self._conf_path(name)
        self._atomic_write(conf_path, conf_text)
        meta_path = self._meta_path(name)
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["pubkey"] = new_pubkey
        self._atomic_write(meta_path, json.dumps(meta, indent=2))
        return ClientRecord(
            name=record.name,
            pubkey=new_pubkey,
            client_ip=record.client_ip,
            conf_path=conf_path,
            client_ip_v6=record.client_ip_v6,
            created_at=record.created_at,
            owner=record.owner,
        )

    def remove_client_files(self, name: str) -> None:
        self.validate_name(name)
        self.load_client(name)
        conf_path = self._conf_path(name)
        if os.path.exists(conf_path):
            os.remove(conf_path)
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
                self.validate_name(name)
            except ClientManagerError:
                self.logger.warning("Skipping client meta with invalid name: %s", fn)
                continue
            try:
                clients.append(self.load_client(name))
            except (ClientManagerError, json.JSONDecodeError):
                continue
        return clients

    def _client_dir_real(self) -> str:
        return os.path.realpath(self.client_dir)

    def _assert_path_inside_client_dir(self, path: str) -> str:
        """Ensure resolved path stays under CLIENT_DIR (defense in depth)."""
        resolved = os.path.realpath(path)
        base = self._client_dir_real()
        if resolved != base and not resolved.startswith(base + os.sep):
            raise ClientManagerError("Path outside CLIENT_DIR")
        return path

    def _safe_client_path(self, name: str, suffix: str) -> str:
        self.validate_name(name)
        path = os.path.join(self.client_dir, f"{name}{suffix}")
        return self._assert_path_inside_client_dir(path)

    def _meta_path(self, name: str) -> str:
        return self._safe_client_path(name, ".json")

    def _conf_path(self, name: str) -> str:
        return self._safe_client_path(name, ".conf")

    def _atomic_write(self, path: str, data: str, mode: int = 0o600) -> None:
        self._assert_path_inside_client_dir(path)
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
