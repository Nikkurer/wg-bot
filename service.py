"""Orchestration: ClientManager + WgAdminClient."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from client_manager import ClientManager, ClientManagerError, ClientRecord
from config import BotConfig
from wg_admin_client import PeerInfo, WgAdminClient, WgAdminError


class ClientServiceError(Exception):
    """Ошибка операции над клиентом."""


@dataclass
class CreateClientResult:
    record: ClientRecord
    conf_text: str


class ClientService:
    """Высокоуровневые операции create / delete / rotate."""

    def __init__(
        self,
        cfg: BotConfig,
        wg_admin: WgAdminClient,
        client_manager: Optional[ClientManager] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.cfg = cfg
        self.wg_admin = wg_admin
        self.clients = client_manager or ClientManager(cfg)
        self.logger = logger or logging.getLogger("client_service")

    async def create_client(self, name: str) -> CreateClientResult:
        self.clients.validate_name(name)
        if self.clients.name_exists(name):
            raise ClientServiceError("Client with that name already exists")

        priv, pub = self.clients.generate_keypair()

        try:
            await self.wg_admin.add_peer(
                public_key=pub,
                description=name,
                persistent_keepalive=self.cfg.persistent_keepalive,
            )
        except WgAdminError as e:
            raise ClientServiceError(f"Failed to add peer on server: {e}") from e

        try:
            peer = await self._get_peer_by_pubkey(pub)
            client_ip, client_ip_v6 = self.clients.parse_peer_ips(peer.allowed_ips)

            if self.cfg.wg_subnet_v6 and not client_ip_v6:
                client_ip_v6 = self.clients.derive_ipv6_from_ipv4(client_ip)
                await self.wg_admin.update_peer(
                    public_key=pub,
                    allowed_ips=[client_ip, client_ip_v6],
                )

            conf_text = self.clients.build_client_conf(priv, client_ip, client_ip_v6)
            record = self.clients.save_client(
                name, pub, client_ip, conf_text, client_ip_v6=client_ip_v6
            )
        except Exception as e:
            self.logger.error("Failed to save client files for %s, rolling back peer", name)
            try:
                await self.wg_admin.remove_peer(pub)
            except WgAdminError as rollback_err:
                self.logger.error("Rollback remove_peer failed: %s", rollback_err)
            if isinstance(e, (WgAdminError, ClientManagerError)):
                raise ClientServiceError(str(e)) from e
            raise ClientServiceError(f"Failed to save client files: {e}") from e

        self.logger.info("Created client %s with IP %s", name, client_ip)
        return CreateClientResult(record=record, conf_text=conf_text)

    async def delete_client(self, name: str) -> None:
        record = self.clients.load_client(name)
        try:
            await self.wg_admin.remove_peer(record.pubkey)
        except WgAdminError as e:
            raise ClientServiceError(f"Failed to remove peer on server: {e}") from e
        try:
            self.clients.remove_client_files(name)
        except ClientManagerError as e:
            raise ClientServiceError(f"Failed to remove client files: {e}") from e
        self.logger.info("Removed client %s", name)

    async def rotate_client(self, name: str) -> CreateClientResult:
        record = self.clients.load_client(name)
        old_pub = record.pubkey
        priv, new_pub = self.clients.generate_keypair()

        try:
            await self.wg_admin.rotate_peer(old_pub, new_pub)
        except WgAdminError as e:
            raise ClientServiceError(f"Failed to rotate peer on server: {e}") from e

        try:
            conf_text = self.clients.build_client_conf(
                priv, record.client_ip, record.client_ip_v6
            )
            updated = self.clients.update_client_after_rotate(name, new_pub, conf_text)
        except Exception as e:
            self.logger.critical(
                "Client %s rotated on server (pubkey=%s...) but conf save failed: %s",
                name,
                new_pub[:8],
                e,
            )
            raise ClientServiceError(
                f"Peer rotated on server but failed to save new conf — manual reissue required"
            ) from e

        self.logger.info("Rotated keys for client %s", name)
        return CreateClientResult(record=updated, conf_text=conf_text)

    async def list_clients_merged(self) -> List[dict]:
        """Merge wg-admin peers with local names."""
        local = {c.name: c for c in self.clients.list_local_clients()}
        try:
            peers = await self.wg_admin.list_peers()
        except WgAdminError as e:
            raise ClientServiceError(f"Failed to list peers: {e}") from e

        by_desc = {p.description: p for p in peers if p.description}
        by_pub = {p.public_key: p for p in peers}

        seen = set()
        result = []
        for name, rec in local.items():
            peer = by_desc.get(name) or by_pub.get(rec.pubkey)
            result.append(_merge_client(name, rec, peer))
            seen.add(rec.pubkey)

        for peer in peers:
            if peer.public_key in seen:
                continue
            name = peer.description or peer.public_key[:8] + "..."
            result.append(_merge_client(name, None, peer))

        return result

    async def _get_peer_by_pubkey(self, public_key: str) -> PeerInfo:
        peers = await self.wg_admin.list_peers()
        for peer in peers:
            if peer.public_key == public_key:
                return peer
        raise ClientServiceError("Peer not found after add")


def _merge_client(name: str, local: Optional[ClientRecord], peer: Optional[PeerInfo]) -> dict:
    return {
        "name": name,
        "ip": local.client_ip if local else (peer.allowed_ips[0] if peer and peer.allowed_ips else ""),
        "ip_v6": local.client_ip_v6 if local else "",
        "pubkey": (local.pubkey if local else peer.public_key if peer else ""),
        "endpoint": peer.endpoint if peer else "",
        "latest_handshake": peer.latest_handshake if peer else None,
        "transfer_rx": peer.transfer_rx if peer else 0,
        "transfer_tx": peer.transfer_tx if peer else 0,
        "has_local_conf": local is not None,
    }
