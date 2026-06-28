import pytest

from client_list import (
    CLIENTS_PAGE_SIZE,
    WG_PUBKEY_LEN,
    client_by_name,
    client_by_pubkey,
    paginate_clients,
    sort_clients,
)
from keyboards import (
    BTN_ADD_CLIENT,
    BTN_PICK_USER,
    CB_CLIENTS_PAGE,
    CB_REMOVE_CONFIRM,
    CB_STATS,
    CB_USER_ADD_ROLE,
    CB_USER_REMOVE_ASK,
    CallbackDataTooLongError,
    TELEGRAM_CALLBACK_DATA_MAX_BYTES,
    add_client_cancel_keyboard,
    add_user_cancel_keyboard,
    add_user_pick_keyboard,
    add_user_role_keyboard,
    build_callback_data,
    client_actions_keyboard,
    clients_pagination_keyboard,
    main_menu,
    operator_remove_confirm_keyboard,
    operator_row_keyboard,
    operators_footer_keyboard,
    parse_callback_index,
    parse_callback_suffix,
    remove_confirm_keyboard,
    rotate_confirm_keyboard,
    validate_callback_data,
)

# WireGuard pubkey: 44-char base64 (fits Telegram callback_data with action prefix).
SAMPLE_PUBKEY = "A" * 43 + "="


def test_client_actions_viewer_has_stats_only():
    kb = client_actions_keyboard(SAMPLE_PUBKEY, is_admin=False)
    assert len(kb.inline_keyboard) == 1
    assert len(kb.inline_keyboard[0]) == 1
    assert kb.inline_keyboard[0][0].callback_data == f"{CB_STATS}:{SAMPLE_PUBKEY}"


def test_client_actions_admin_orphan_has_remove_only():
    kb = client_actions_keyboard(SAMPLE_PUBKEY, is_admin=True, has_local_conf=False)
    assert len(kb.inline_keyboard[0]) == 2
    callbacks = [btn.callback_data for btn in kb.inline_keyboard[0]]
    assert callbacks == [f"stats:{SAMPLE_PUBKEY}", f"remove:ask:{SAMPLE_PUBKEY}"]


def test_client_actions_admin_has_rotate_and_remove():
    kb = client_actions_keyboard(SAMPLE_PUBKEY, is_admin=True)
    assert len(kb.inline_keyboard[0]) == 3
    callbacks = [btn.callback_data for btn in kb.inline_keyboard[0]]
    assert callbacks == [
        f"stats:{SAMPLE_PUBKEY}",
        f"rotate:ask:{SAMPLE_PUBKEY}",
        f"remove:ask:{SAMPLE_PUBKEY}",
    ]


def test_client_callbacks_use_pubkey_not_list_index():
    kb = client_actions_keyboard(SAMPLE_PUBKEY, is_admin=True)
    for btn in kb.inline_keyboard[0]:
        suffix = btn.callback_data.split(":", 1)[-1]
        if btn.callback_data.startswith("stats:"):
            assert suffix == SAMPLE_PUBKEY
        else:
            assert suffix.endswith(SAMPLE_PUBKEY)
        assert suffix.isdigit() is False


def test_callbacks_fit_telegram_limit():
    inline_keyboards = [
        rotate_confirm_keyboard(SAMPLE_PUBKEY),
        remove_confirm_keyboard(SAMPLE_PUBKEY),
        client_actions_keyboard(SAMPLE_PUBKEY, is_admin=True),
        clients_pagination_keyboard(99, 100),
        add_client_cancel_keyboard(),
        add_user_cancel_keyboard(),
        add_user_role_keyboard(123456789),
        operator_remove_confirm_keyboard(123456789),
        operators_footer_keyboard(),
    ]
    for kb in inline_keyboards:
        for row in kb.inline_keyboard:
            for btn in row:
                assert (
                    len(btn.callback_data.encode("utf-8"))
                    <= TELEGRAM_CALLBACK_DATA_MAX_BYTES
                )

    pick_kb = add_user_pick_keyboard()
    assert pick_kb.keyboard[0][0].request_users.request_id == 1


def test_client_action_callbacks_with_full_length_pubkey():
    assert len(SAMPLE_PUBKEY) == WG_PUBKEY_LEN
    data = build_callback_data(CB_REMOVE_CONFIRM, SAMPLE_PUBKEY)
    assert len(data.encode("utf-8")) <= TELEGRAM_CALLBACK_DATA_MAX_BYTES


def test_build_callback_data_within_limit():
    data = build_callback_data("remove:confirm", "a" * 40)
    assert len(data.encode("utf-8")) <= TELEGRAM_CALLBACK_DATA_MAX_BYTES


def test_build_callback_data_raises_when_too_long():
    with pytest.raises(CallbackDataTooLongError, match="65 bytes"):
        build_callback_data("remove:confirm", "x" * 50)


def test_validate_callback_data_accepts_short_string():
    assert validate_callback_data("rotate:cancel") == "rotate:cancel"


def test_clients_pagination_single_page_returns_none():
    assert clients_pagination_keyboard(0, 1) is None


def test_clients_pagination_multi_page():
    kb = clients_pagination_keyboard(1, 3)
    callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row]
    assert f"{CB_CLIENTS_PAGE}:0" in callbacks
    assert f"{CB_CLIENTS_PAGE}:1" in callbacks
    assert f"{CB_CLIENTS_PAGE}:2" in callbacks


def test_parse_callback_index_for_pagination():
    assert parse_callback_index("clients:page:12", CB_CLIENTS_PAGE) == 12


def test_parse_callback_suffix_for_pubkey():
    assert parse_callback_suffix(f"stats:{SAMPLE_PUBKEY}", CB_STATS) == SAMPLE_PUBKEY
    assert (
        parse_callback_suffix(f"rotate:ask:{SAMPLE_PUBKEY}", "rotate:ask")
        == SAMPLE_PUBKEY
    )


def test_admin_main_menu_has_add_client_button():
    kb = main_menu(is_admin=True)
    labels = {btn.text for row in kb.keyboard for btn in row}
    assert BTN_ADD_CLIENT in labels


def test_viewer_main_menu_has_no_add_client_button():
    kb = main_menu(is_admin=False)
    labels = {btn.text for row in kb.keyboard for btn in row}
    assert BTN_ADD_CLIENT not in labels


def test_operator_row_superadmin_has_no_remove():
    assert operator_row_keyboard(111, "superadmin") is None


def test_operator_row_admin_has_remove():
    kb = operator_row_keyboard(222, "admin")
    assert kb.inline_keyboard[0][0].callback_data == f"{CB_USER_REMOVE_ASK}:222"


def test_add_user_pick_keyboard_has_request_users():
    kb = add_user_pick_keyboard()
    btn = kb.keyboard[0][0]
    assert btn.text == BTN_PICK_USER
    assert btn.request_users is not None
    assert btn.request_users.request_id == 1
    assert btn.request_users.max_quantity == 1


def test_add_user_role_keyboard_has_admin_and_user():
    kb = add_user_role_keyboard(333)
    callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row]
    assert f"{CB_USER_ADD_ROLE}:333:admin" in callbacks
    assert f"{CB_USER_ADD_ROLE}:333:user" in callbacks
