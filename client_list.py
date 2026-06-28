"""Helpers for sorted client lists, pagination and index-based callbacks."""

from __future__ import annotations

from typing import List, Tuple

CLIENTS_PAGE_SIZE = 8


def sort_clients(clients: List[dict]) -> List[dict]:
    return sorted(clients, key=lambda c: c["name"])


def paginate_clients(
    clients: List[dict], page: int, *, page_size: int = CLIENTS_PAGE_SIZE
) -> Tuple[List[dict], int, int]:
    """Return slice for page, clamped page index, and total page count."""
    total = len(clients)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    return clients[start : start + page_size], page, total_pages


def global_client_index(page: int, page_index: int, *, page_size: int = CLIENTS_PAGE_SIZE) -> int:
    return page * page_size + page_index


def client_index_in_sorted(clients: List[dict], name: str) -> int | None:
    sorted_list = sort_clients(clients)
    for i, c in enumerate(sorted_list):
        if c["name"] == name:
            return i
    return None
