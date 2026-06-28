from operator_add import (
    ADD_USER_REQUEST_ID,
    contact_user_id_or_error,
    format_person_name,
)


def test_format_person_name_from_first_name():
    assert format_person_name(first_name="Alice", user_id=123) == "Alice"


def test_format_person_name_falls_back_to_username():
    assert format_person_name(username="alice", user_id=123) == "@alice"


def test_format_person_name_falls_back_to_id():
    assert format_person_name(user_id=123) == "123"


def test_contact_user_id_or_error_missing():
    user_id, error = contact_user_id_or_error(None)
    assert user_id is None
    assert error


def test_contact_user_id_or_error_ok():
    user_id, error = contact_user_id_or_error(987654321)
    assert user_id == 987654321
    assert error is None


def test_add_user_request_id_is_stable():
    assert ADD_USER_REQUEST_ID == 1
