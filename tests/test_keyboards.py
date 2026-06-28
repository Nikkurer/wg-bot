from keyboards import (
    BTN_ADD_CLIENT,
    CB_STATS,
    add_client_cancel_keyboard,
    client_actions_keyboard,
    main_menu,
    remove_confirm_keyboard,
    rotate_confirm_keyboard,
)


def test_client_actions_viewer_has_stats_only():
    kb = client_actions_keyboard("alice", is_admin=False)
    assert len(kb.inline_keyboard) == 1
    assert len(kb.inline_keyboard[0]) == 1
    assert kb.inline_keyboard[0][0].callback_data == f"{CB_STATS}:alice"


def test_client_actions_admin_has_rotate_and_remove():
    kb = client_actions_keyboard("bob", is_admin=True)
    assert len(kb.inline_keyboard[0]) == 3
    callbacks = [btn.callback_data for btn in kb.inline_keyboard[0]]
    assert callbacks[0] == f"{CB_STATS}:bob"
    assert callbacks[1] == "rotate:ask:bob"
    assert callbacks[2] == "remove:ask:bob"


def test_callbacks_fit_telegram_limit():
    long_name = "a" * 49
    keyboards = [
        rotate_confirm_keyboard(long_name),
        remove_confirm_keyboard(long_name),
        client_actions_keyboard(long_name, is_admin=True),
        add_client_cancel_keyboard(),
    ]
    for kb in keyboards:
        for row in kb.inline_keyboard:
            for btn in row:
                assert len(btn.callback_data.encode("utf-8")) <= 64


def test_admin_main_menu_has_add_client_button():
    kb = main_menu(is_admin=True)
    labels = {btn.text for row in kb.keyboard for btn in row}
    assert BTN_ADD_CLIENT in labels


def test_viewer_main_menu_has_no_add_client_button():
    kb = main_menu(is_admin=False)
    labels = {btn.text for row in kb.keyboard for btn in row}
    assert BTN_ADD_CLIENT not in labels
