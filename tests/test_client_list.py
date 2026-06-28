from client_list import (
    CLIENTS_PAGE_SIZE,
    client_index_in_sorted,
    global_client_index,
    paginate_clients,
    sort_clients,
)


def _clients(names):
    return [{"name": n, "ip": f"10.0.0.{i}"} for i, n in enumerate(names, 1)]


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


def test_global_client_index():
    assert global_client_index(0, 3) == 3
    assert global_client_index(1, 2) == CLIENTS_PAGE_SIZE + 2


def test_client_index_in_sorted():
    clients = sort_clients(_clients(["bob", "alice"]))
    assert client_index_in_sorted(clients, "alice") == 0
    assert client_index_in_sorted(clients, "missing") is None
