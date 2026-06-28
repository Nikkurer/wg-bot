from client_list import (
    CLIENTS_PAGE_SIZE,
    WG_PUBKEY_LEN,
    client_by_name,
    client_by_pubkey,
    paginate_clients,
    sort_clients,
)

SAMPLE_PUBKEY = "A" * 43 + "="
ALICE_PUBKEY = "C" * 43 + "="
BOB_PUBKEY = "D" * 43 + "="


def _clients(names):
    pubkeys = {
        "alice": ALICE_PUBKEY,
        "bob": BOB_PUBKEY,
        "carol": SAMPLE_PUBKEY,
    }
    return [
        {
            "name": n,
            "ip": f"10.0.0.{i}",
            "pubkey": pubkeys.get(n, SAMPLE_PUBKEY),
        }
        for i, n in enumerate(names, 1)
    ]


def test_sort_clients_by_name():
    clients = _clients(["bob", "alice", "carol"])
    assert [c["name"] for c in sort_clients(clients)] == ["alice", "bob", "carol"]


def test_paginate_clients_first_page():
    clients = _clients([f"c{i}" for i in range(10)])
    page_clients, page, total = paginate_clients(clients, 0)
    assert page == 0
    assert total == 2
    assert len(page_clients) == CLIENTS_PAGE_SIZE


def test_paginate_clients_last_page():
    clients = _clients([f"c{i}" for i in range(10)])
    page_clients, page, total = paginate_clients(clients, 1)
    assert page == 1
    assert total == 2
    assert len(page_clients) == 2


def test_paginate_clamps_page():
    clients = _clients([f"c{i}" for i in range(5)])
    _, page, total = paginate_clients(clients, 99)
    assert page == 0
    assert total == 1


def test_client_by_pubkey():
    clients = sort_clients(_clients(["bob", "alice"]))
    assert client_by_pubkey(clients, ALICE_PUBKEY)["name"] == "alice"
    assert client_by_pubkey(clients, BOB_PUBKEY)["name"] == "bob"
    assert client_by_pubkey(clients, "missing") is None


def test_client_by_name():
    clients = sort_clients(_clients(["bob", "alice"]))
    assert client_by_name(clients, "alice")["pubkey"] == ALICE_PUBKEY
    assert client_by_name(clients, "missing") is None


def test_wg_pubkey_len_constant():
    assert len(SAMPLE_PUBKEY) == WG_PUBKEY_LEN
