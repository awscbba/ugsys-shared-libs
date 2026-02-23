"""Tests for TokenValidator."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from src.token_validator import TokenValidator

SECRET = "test-secret"
ALGORITHM = "HS256"


def _make_token(payload: dict) -> str:
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def _base_payload(**overrides) -> dict:
    return {
        "sub": "user-123",
        "email": "user@example.com",
        "roles": ["member"],
        "isAdmin": False,
        "type": "access",
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
        **overrides,
    }


class TestTokenValidatorLocal:
    def setup_method(self):
        self.validator = TokenValidator(jwt_secret=SECRET, jwt_algorithm=ALGORITHM)

    def test_valid_token_returns_payload(self):
        token = _make_token(_base_payload())
        result = self.validator.validate_local(token)
        assert result is not None
        assert result.sub == "user-123"
        assert result.email == "user@example.com"
        assert result.roles == ["member"]
        assert result.is_admin is False

    def test_expired_token_returns_none(self):
        token = _make_token(
            _base_payload(exp=datetime.now(tz=timezone.utc) - timedelta(hours=1))
        )
        assert self.validator.validate_local(token) is None

    def test_invalid_signature_returns_none(self):
        token = jwt.encode(_base_payload(), "wrong-secret", algorithm=ALGORITHM)
        assert self.validator.validate_local(token) is None

    def test_no_secret_returns_none(self):
        validator = TokenValidator()
        token = _make_token(_base_payload())
        assert validator.validate_local(token) is None

    def test_admin_flag_mapped(self):
        token = _make_token(_base_payload(isAdmin=True))
        result = self.validator.validate_local(token)
        assert result is not None
        assert result.is_admin is True

    def test_validate_delegates_to_local(self):
        token = _make_token(_base_payload())
        result = self.validator.validate(token)
        assert result is not None
        assert result.sub == "user-123"
