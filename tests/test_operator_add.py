from operator_add import (
    ADD_USER_REQUEST_ID,
    contact_user_id_or_error,
    format_operator_display,
    format_person_name,
    pending_profile_from_fsm,
)


def test_format_person_name_from_first_name():
    assert (
        format_person_name(first_name="Alice", last_name="Smith", user_id=123)
        == "Alice Smith"
    )


def test_format_operator_display_with_username():
    label = format_operator_display(
        {
            "id": 123,
            "first_name": "Alice",
            "last_name": "Smith",
            "username": "alice",
        }
    )
    assert label == "Alice Smith (@alice)"


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


def test_pending_profile_from_fsm():
    data = {
        "pending_user_id": 123456789,
        "pending_first_name": "Ivan",
        "pending_last_name": "Petrov",
        "pending_username": "ivan",
    }
    profile = pending_profile_from_fsm(data, 123456789)
    assert profile == {
        "first_name": "Ivan",
        "last_name": "Petrov",
        "username": "ivan",
    }


def test_pending_profile_from_fsm_string_id():
    data = {
        "pending_user_id": "123456789",
        "pending_first_name": "Ivan",
    }
    profile = pending_profile_from_fsm(data, 123456789)
    assert profile == {"first_name": "Ivan"}


def test_pending_profile_from_fsm_mismatch():
    data = {"pending_user_id": 111, "pending_first_name": "Ivan"}
    assert pending_profile_from_fsm(data, 222) == {}


def test_add_user_request_id_is_stable():
    assert ADD_USER_REQUEST_ID == 1
