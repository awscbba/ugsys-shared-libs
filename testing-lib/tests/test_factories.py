"""Tests for shared test factories."""

from datetime import datetime, timezone

import jwt
import pytest

from src.factories import UserFactory, make_token


class TestMakeToken:
    def test_returns_valid_jwt(self):
        token = make_token(secret="test-secret")
        payload = jwt.decode(token, "test-secret", algorithms=["HS256"])
        assert "sub" in payload
        assert payload["email"] == "test@example.com"

    def test_custom_roles(self):
        token = make_token(roles=["admin", "member"], secret="s")
        payload = jwt.decode(token, "s", algorithms=["HS256"])
        assert payload["roles"] == ["admin", "member"]

    def test_expired_token(self):
        token = make_token(expires_in_hours=-1, secret="s")
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, "s", algorithms=["HS256"])


class TestUserFactory:
    def test_build_returns_dict_with_required_fields(self):
        user = UserFactory.build()
        assert "id" in user
        assert "email" in user
        assert user["isActive"] is True
        assert user["isAdmin"] is False

    def test_build_admin(self):
        admin = UserFactory.build_admin()
        assert admin["isAdmin"] is True
        assert "admin" in admin["roles"]

    def test_build_with_overrides(self):
        user = UserFactory.build(email="custom@example.com", isActive=False)
        assert user["email"] == "custom@example.com"
        assert user["isActive"] is False

    def test_each_build_has_unique_id(self):
        ids = {UserFactory.build()["id"] for _ in range(10)}
        assert len(ids) == 10
