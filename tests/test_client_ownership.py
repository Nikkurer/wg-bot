"""Tests for client_ownership.py."""

import json
import os
import tempfile

import pytest

from client_ownership import (
    can_manage_client,
    can_view_client,
    filter_clients_for_actor,
    format_owner_label,
)
from users import UserManager


@pytest.fixture
def temp_user_file():
    temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json")
    temp_file.write("[]")
    temp_file.close()
    yield temp_file.name
    if os.path.exists(temp_file.name):
        os.remove(temp_file.name)


def _client(**kwargs):
    base = {
        "name": "alice",
        "display_name": "alice",
        "storage_name": "alice",
        "pubkey": "pub",
        "has_local_conf": True,
        "owner": 100,
    }
    base.update(kwargs)
    return base


def test_format_owner_label_legacy(temp_user_file):
    um = UserManager(temp_user_file)
    assert format_owner_label(None, um) == "без владельца (legacy)"


def test_format_owner_label_known_user(temp_user_file):
    with open(temp_user_file, "w", encoding="utf-8") as f:
        json.dump([{"id": 100, "role": "user", "first_name": "Alice"}], f)
    um = UserManager(temp_user_file)
    assert format_owner_label(100, um) == "Alice"


def test_format_owner_label_deleted_operator(temp_user_file):
    um = UserManager(temp_user_file)
    assert format_owner_label(123456789, um) == "ID 123456789 <deleted>"


def test_user_can_view_own_client(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(100, "user")
    assert can_view_client(100, um, _client()) is True


def test_user_cannot_view_other_or_legacy_or_orphan(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(100, "user")
    assert can_view_client(100, um, _client(owner=200)) is False
    assert can_view_client(100, um, _client(owner=None)) is False
    assert can_view_client(
        100, um, _client(storage_name=None, has_local_conf=False, owner=None)
    ) is False


def test_admin_can_view_all(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(1, "admin")
    assert can_view_client(1, um, _client(owner=None)) is True
    assert can_view_client(
        1, um, _client(storage_name=None, has_local_conf=False, owner=None)
    ) is True


def test_user_can_manage_own_client(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(100, "user")
    assert can_manage_client(100, um, _client()) is True


def test_user_cannot_manage_legacy_or_other(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(100, "user")
    assert can_manage_client(100, um, _client(owner=None)) is False
    assert can_manage_client(100, um, _client(owner=200)) is False


def test_filter_clients_for_user(temp_user_file):
    um = UserManager(temp_user_file)
    um.add_user(100, "user")
    clients = [
        _client(name="mine", owner=100),
        _client(name="other", owner=200),
        _client(name="legacy", owner=None),
    ]
    filtered = filter_clients_for_actor(clients, 100, um)
    assert [c["name"] for c in filtered] == ["mine"]
