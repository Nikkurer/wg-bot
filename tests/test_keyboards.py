from keyboards import (
    BTN_ADD_CLIENT,
    CB_CLIENTS_PAGE,
    CB_STATS,
    CB_USER_ADD_ROLE,
    CB_USER_REMOVE_ASK,
    add_client_cancel_keyboard,
    add_user_cancel_keyboard,
    add_user_role_keyboard,
    client_actions_keyboard,
    clients_pagination_keyboard,
    main_menu,
    operator_remove_confirm_keyboard,
    operator_row_keyboard,
    operators_footer_keyboard,
    parse_callback_index,
    remove_confirm_keyboard,
    rotate_confirm_keyboard,
)


def test_client_actions_viewer_has_stats_only():
    kb = client_actions_keyboard(3, is_admin=False)
    assert len(kb.inline_keyboard) == 1
    assert len(kb.inline_keyboard[0]) == 1
    assert kb.inline_keyboard[0][0].callback_data == f"{CB_STATS}:3"


def test_client_actions_admin_has_rotate_and_remove():
    kb = client_actions_keyboard(5, is_admin=True)
    assert len(kb.inline_keyboard[0]) == 3
    callbacks = [btn.callback_data for btn in kb.inline_keyboard[0]]
    assert callbacks == ["stats:5", "rotate:ask:5", "remove:ask:5"]


def test_callbacks_fit_telegram_limit():
    keyboards = [
        rotate_confirm_keyboard(99999),
        remove_confirm_keyboard(99999),
        client_actions_keyboard(99999, is_admin=True),
        clients_pagination_keyboard(99, 100),
        add_client_cancel_keyboard(),
        add_user_cancel_keyboard(),
        add_user_role_keyboard(123456789),
        operator_remove_confirm_keyboard(123456789),
        operators_footer_keyboard(),
    ]
    for kb in keyboards:
        for row in kb.inline_keyboard:
            for btn in row:
                assert len(btn.callback_data.encode("utf-8")) <= 64


def test_clients_pagination_single_page_returns_none():
    assert clients_pagination_keyboard(0, 1) is None


def test_clients_pagination_multi_page():
    kb = clients_pagination_keyboard(1, 3)
    callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row]
    assert f"{CB_CLIENTS_PAGE}:0" in callbacks
    assert f"{CB_CLIENTS_PAGE}:1" in callbacks
    assert f"{CB_CLIENTS_PAGE}:2" in callbacks


def test_parse_callback_index():
    assert parse_callback_index("rotate:ask:12", "rotate:ask") == 12
    assert parse_callback_index("stats:0", "stats") == 0


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


def test_add_user_role_keyboard_has_admin_and_user():
    kb = add_user_role_keyboard(333)
    callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row]
    assert f"{CB_USER_ADD_ROLE}:333:admin" in callbacks
    assert f"{CB_USER_ADD_ROLE}:333:user" in callbacks
