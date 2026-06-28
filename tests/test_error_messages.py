"""Tests for error_messages.py."""

from client_manager import ClientManagerError
from error_messages import (
    GENERIC_CLIENT_ERROR,
    GENERIC_ERROR,
    admin_diagnostic_detail,
    format_drift_error,
    user_facing_error,
)
from messages import (
    ACCESS_DENIED,
    CLIENT_ALREADY_EXISTS,
    INVALID_CLIENT_NAME,
)
from service import ClientServiceError
from users import UserManagerError


class TestUserFacingError:
    def test_user_manager_error_passthrough(self):
        exc = UserManagerError("Только superadmin может назначать роль admin")
        assert user_facing_error(exc) == str(exc)

    def test_safe_client_service_message(self):
        exc = ClientServiceError(CLIENT_ALREADY_EXISTS)
        assert user_facing_error(exc) == CLIENT_ALREADY_EXISTS

    def test_access_denied_passthrough(self):
        exc = ClientServiceError(ACCESS_DENIED)
        assert user_facing_error(exc) == ACCESS_DENIED

    def test_wrapped_invalid_client_name_via_client_service(self):
        exc = ClientServiceError(INVALID_CLIENT_NAME)
        assert user_facing_error(exc) == INVALID_CLIENT_NAME

    def test_wg_admin_wrapped_message_is_generic(self):
        exc = ClientServiceError(
            "Failed to list peers: wg-admin request failed: [Errno 2] No such file"
        )
        assert user_facing_error(exc) == GENERIC_CLIENT_ERROR

    def test_client_manager_path_leak_is_generic(self):
        exc = ClientManagerError("Path outside CLIENT_DIR")
        assert user_facing_error(exc) == GENERIC_CLIENT_ERROR

    def test_invalid_client_name_passthrough(self):
        exc = ClientManagerError(INVALID_CLIENT_NAME)
        assert user_facing_error(exc) == INVALID_CLIENT_NAME

    def test_unknown_exception_is_generic(self):
        assert user_facing_error(RuntimeError("secret traceback line")) == GENERIC_ERROR


class TestAdminDiagnostic:
    def test_escapes_html(self):
        assert admin_diagnostic_detail(Exception("<script>")) == "&lt;script&gt;"

    def test_format_drift_error(self):
        msg = format_drift_error(Exception("socket /run/wg-admin.sock"))
        assert "socket /run/wg-admin.sock" in msg
        assert msg.startswith("❌ Ошибка drift check:")
