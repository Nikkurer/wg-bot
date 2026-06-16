"""Tests for wg_admin_client.py."""
import httpx
import pytest

from wg_admin_client import (
    DriftReport,
    InterfaceStatus,
    PeerInfo,
    WgAdminClient,
    WgAdminError,
)


def _ok(data=None):
    return httpx.Response(200, json={"status": "ok", "data": data or {}})


def _err(status: int, message: str):
    return httpx.Response(status, json={"status": "error", "message": message})


@pytest.fixture
def mock_transport():
    routes = {}

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key not in routes:
            return httpx.Response(404, json={"status": "error", "message": "not found"})
        return routes[key](request)

    transport = httpx.MockTransport(handler)
    return routes, transport


@pytest.fixture
async def client(mock_transport):
    routes, transport = mock_transport
    http = httpx.AsyncClient(transport=transport, base_url="http://wg-admin")
    wg = WgAdminClient("/fake.sock", client=http)
    wg._routes = routes  # for tests
    yield wg
    await wg.close()


class TestWgAdminClient:
    @pytest.mark.asyncio
    async def test_add_peer(self, client):
        seen = {}

        def add_handler(request):
            import json

            seen["json"] = json.loads(request.content)
            return _ok()

        client._routes[("POST", "/peer/add")] = add_handler
        await client.add_peer(
            "pubkey123",
            ["10.66.66.2/32", "fd66:66::2/128"],
            description="alice",
            persistent_keepalive=25,
        )
        assert seen["json"]["public_key"] == "pubkey123"
        assert seen["json"]["description"] == "alice"

    @pytest.mark.asyncio
    async def test_remove_peer(self, client):
        seen = {}

        def handler(request):
            import json

            seen["json"] = json.loads(request.content)
            return _ok()

        client._routes[("POST", "/peer/remove")] = handler
        await client.remove_peer("pubkey123")
        assert seen["json"]["public_key"] == "pubkey123"

    @pytest.mark.asyncio
    async def test_rotate_peer(self, client):
        seen = {}

        def handler(request):
            import json

            seen["json"] = json.loads(request.content)
            return _ok()

        client._routes[("POST", "/peer/rotate")] = handler
        await client.rotate_peer("old", "new")
        assert seen["json"]["old_public_key"] == "old"
        assert seen["json"]["new_public_key"] == "new"

    @pytest.mark.asyncio
    async def test_list_peers(self, client):
        client._routes[("GET", "/peer/list")] = lambda r: _ok(
            {
                "peers": [
                    {
                        "public_key": "pk1",
                        "allowed_ips": ["10.66.66.2/32"],
                        "description": "alice",
                        "transfer_rx": 100,
                        "transfer_tx": 200,
                        "latest_handshake": 1690000100,
                    }
                ]
            }
        )
        peers = await client.list_peers()
        assert len(peers) == 1
        assert peers[0] == PeerInfo(
            public_key="pk1",
            allowed_ips=["10.66.66.2/32"],
            description="alice",
            endpoint="",
            latest_handshake=1690000100,
            transfer_rx=100,
            transfer_tx=200,
            persistent_keepalive=None,
        )

    @pytest.mark.asyncio
    async def test_interface_status(self, client):
        client._routes[("GET", "/interface/status")] = lambda r: _ok(
            {
                "name": "wg-ru-clients",
                "public_key": "serverpk",
                "state": "UP",
                "peers": [],
            }
        )
        st = await client.interface_status()
        assert st == InterfaceStatus(
            name="wg-ru-clients",
            public_key="serverpk",
            state="UP",
            peers=[],
        )

    @pytest.mark.asyncio
    async def test_detect_drift(self, client):
        client._routes[("GET", "/peer/drift")] = lambda r: _ok(
            {
                "in_sync": False,
                "only_in_storage": [{"public_key": "a", "allowed_ips": ["10.0.0.1/32"]}],
                "only_in_wireguard": [],
                "mismatch": [],
            }
        )
        report = await client.detect_drift()
        assert isinstance(report, DriftReport)
        assert report.in_sync is False
        assert len(report.only_in_storage) == 1

    @pytest.mark.asyncio
    async def test_api_error(self, client):
        client._routes[("GET", "/peer/list")] = lambda r: _err(500, "boom")
        with pytest.raises(WgAdminError, match="boom"):
            await client.list_peers()

    @pytest.mark.asyncio
    async def test_status_error_payload(self, client):
        client._routes[("POST", "/peer/add")] = lambda r: httpx.Response(
            200, json={"status": "error", "message": "invalid key"}
        )
        with pytest.raises(WgAdminError, match="invalid key"):
            await client.add_peer("bad", ["10.0.0.1/32"])
