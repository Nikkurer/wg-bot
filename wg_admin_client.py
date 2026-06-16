"""HTTP-клиент wg-admin API over Unix socket."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx


class WgAdminError(Exception):
    """Ошибка вызова wg-admin API."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class PeerInfo:
    public_key: str
    allowed_ips: List[str]
    description: str = ""
    endpoint: str = ""
    latest_handshake: Optional[int] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    persistent_keepalive: Optional[int] = None


@dataclass(frozen=True)
class InterfaceStatus:
    name: str
    public_key: str
    state: str
    peers: List[PeerInfo] = field(default_factory=list)


@dataclass(frozen=True)
class DriftPeer:
    public_key: str
    allowed_ips: List[str]


@dataclass(frozen=True)
class DriftMismatch:
    public_key: str
    storage: DriftPeer
    wireguard: DriftPeer


@dataclass(frozen=True)
class DriftReport:
    in_sync: bool
    only_in_storage: List[DriftPeer] = field(default_factory=list)
    only_in_wireguard: List[DriftPeer] = field(default_factory=list)
    mismatch: List[DriftMismatch] = field(default_factory=list)


class WgAdminClient:
    """Async-клиент wg-admin over Unix socket."""

    def __init__(self, socket_path: str, client: Optional[httpx.AsyncClient] = None):
        self._socket_path = socket_path
        self._client = client
        self._owned = client is None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            transport = httpx.AsyncHTTPTransport(uds=self._socket_path)
            self._client = httpx.AsyncClient(
                transport=transport,
                base_url="http://wg-admin",
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        if self._owned and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def add_peer(
        self,
        public_key: str,
        allowed_ips: List[str],
        description: str = "",
        persistent_keepalive: Optional[int] = 25,
    ) -> None:
        body: Dict[str, Any] = {
            "public_key": public_key,
            "allowed_ips": allowed_ips,
            "description": description,
        }
        if persistent_keepalive is not None:
            body["persistent_keepalive"] = persistent_keepalive
        await self._request("POST", "/peer/add", json=body)

    async def remove_peer(self, public_key: str) -> None:
        await self._request("POST", "/peer/remove", json={"public_key": public_key})

    async def rotate_peer(self, old_public_key: str, new_public_key: str) -> None:
        await self._request(
            "POST",
            "/peer/rotate",
            json={
                "old_public_key": old_public_key,
                "new_public_key": new_public_key,
            },
        )

    async def list_peers(self) -> List[PeerInfo]:
        data = await self._request("GET", "/peer/list")
        peers = data.get("peers") or []
        return [_parse_peer(p) for p in peers]

    async def interface_status(self) -> InterfaceStatus:
        data = await self._request("GET", "/interface/status")
        peers = [_parse_peer(p) for p in (data.get("peers") or [])]
        return InterfaceStatus(
            name=data.get("name", ""),
            public_key=data.get("public_key", ""),
            state=data.get("state", ""),
            peers=peers,
        )

    async def detect_drift(self) -> DriftReport:
        data = await self._request("GET", "/peer/drift")
        return DriftReport(
            in_sync=bool(data.get("in_sync")),
            only_in_storage=[_parse_drift_peer(p) for p in data.get("only_in_storage") or []],
            only_in_wireguard=[
                _parse_drift_peer(p) for p in data.get("only_in_wireguard") or []
            ],
            mismatch=[_parse_drift_mismatch(m) for m in data.get("mismatch") or []],
        )

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        client = await self._http()
        try:
            response = await client.request(method, path, json=json)
        except httpx.RequestError as e:
            raise WgAdminError(f"wg-admin request failed: {e}") from e

        if response.status_code >= 400:
            msg = _error_message(response)
            raise WgAdminError(msg, status_code=response.status_code)

        try:
            payload = response.json()
        except ValueError as e:
            raise WgAdminError(f"Invalid JSON from wg-admin: {e}") from e

        if payload.get("status") != "ok":
            raise WgAdminError(payload.get("message") or "wg-admin error")

        data = payload.get("data")
        if data is None:
            return {}
        if not isinstance(data, dict):
            return {"result": data}
        return data


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("message"):
            return str(payload["message"])
    except ValueError:
        pass
    text = response.text.strip()
    return text or f"HTTP {response.status_code}"


def _parse_peer(raw: Dict[str, Any]) -> PeerInfo:
    return PeerInfo(
        public_key=raw.get("public_key", ""),
        allowed_ips=list(raw.get("allowed_ips") or []),
        description=raw.get("description") or "",
        endpoint=raw.get("endpoint") or "",
        latest_handshake=raw.get("latest_handshake"),
        transfer_rx=int(raw.get("transfer_rx") or 0),
        transfer_tx=int(raw.get("transfer_tx") or 0),
        persistent_keepalive=raw.get("persistent_keepalive"),
    )


def _parse_drift_peer(raw: Dict[str, Any]) -> DriftPeer:
    return DriftPeer(
        public_key=raw.get("public_key", ""),
        allowed_ips=list(raw.get("allowed_ips") or []),
    )


def _parse_drift_mismatch(raw: Dict[str, Any]) -> DriftMismatch:
    return DriftMismatch(
        public_key=raw.get("public_key", ""),
        storage=_parse_drift_peer(raw.get("storage") or {}),
        wireguard=_parse_drift_peer(raw.get("wireguard") or {}),
    )
