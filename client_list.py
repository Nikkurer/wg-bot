"""Helpers for sorted client lists, pagination and pubkey-based callbacks."""

from __future__ import annotations

from typing import List, Optional, Tuple

CLIENTS_PAGE_SIZE = 8

# WireGuard public keys are 44-char base64; fits Telegram callback_data with prefix.
WG_PUBKEY_LEN = 44


def sort_clients(clients: List[dict]) -> List[dict]:
    return sorted(clients, key=lambda c: c.get("display_name", c["name"]))


def paginate_clients(
    clients: List[dict], page: int, *, page_size: int = CLIENTS_PAGE_SIZE
) -> Tuple[List[dict], int, int]:
    """Return slice for page, clamped page index, and total page count."""
    total = len(clients)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    return clients[start : start + page_size], page, total_pages


def client_by_pubkey(clients: List[dict], pubkey: str) -> Optional[dict]:
    for c in clients:
        if c.get("pubkey") == pubkey:
            return c
    return None


def client_by_name(clients: List[dict], name: str) -> Optional[dict]:
    for c in clients:
        if c.get("display_name", c["name"]) == name:
            return c
        storage = c.get("storage_name")
        if storage and storage == name:
            return c
    return None
