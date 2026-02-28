"""Tests for TokenValidator — RS256 enforcement and algorithm restriction."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ugsys_auth_client.token_validator import TokenValidator

# ── Test key material ─────────────────────────────────────────────────────────

HS_SECRET = "test-secret"

# Generate an RSA key pair for RS256 tests (done once at module level)
_RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PUBLIC_KEY = _RSA_PRIVATE_KEY.public_key()
_RSA_PRIVATE_PEM = _RSA_PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_RSA_PUBLIC_PEM = _RSA_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
_KID = "test-key-id"


def _hs_token(payload: dict) -> str:
    return jwt.encode(payload, HS_SECRET, algorithm="HS256")


def _rs256_token(payload: dict, kid: str = _KID) -> str:
    return jwt.encode(
        payload,
        _RSA_PRIVATE_PEM,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _base_payload(**overrides: object) -> dict:
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


def _make_jwks_response(public_key=_RSA_PUBLIC_KEY, kid: str = _KID) -> dict:
    """Build a minimal JWKS response dict for the given RSA public key."""
    from jwt.algorithms import RSAAlgorithm

    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    return {"keys": [jwk_dict]}


# ── HS256 local validation (legacy path — unchanged) ─────────────────────────


class TestHS256LocalValidation:
    def setup_method(self) -> None:
        self.validator = TokenValidator(jwt_secret=HS_SECRET, jwt_algorithm="HS256")

    def test_valid_token_returns_payload(self) -> None:
        token = _hs_token(_base_payload())
        result = self.validator.validate_local(token)
        assert result is not None
        assert result.sub == "user-123"
        assert result.email == "user@example.com"

    def test_expired_token_returns_none(self) -> None:
        token = _hs_token(_base_payload(exp=datetime.now(tz=timezone.utc) - timedelta(hours=1)))
        assert self.validator.validate_local(token) is None

    def test_invalid_signature_returns_none(self) -> None:
        token = jwt.encode(_base_payload(), "wrong-secret", algorithm="HS256")
        assert self.validator.validate_local(token) is None

    def test_no_secret_returns_none(self) -> None:
        validator = TokenValidator()
        token = _hs_token(_base_payload())
        assert validator.validate_local(token) is None

    def test_admin_flag_mapped(self) -> None:
        token = _hs_token(_base_payload(isAdmin=True))
        result = self.validator.validate_local(token)
        assert result is not None
        assert result.is_admin is True

    def test_validate_delegates_to_local(self) -> None:
        token = _hs_token(_base_payload())
        result = self.validator.validate(token)
        assert result is not None
        assert result.sub == "user-123"


# ── Algorithm restriction (RS256 mode) ───────────────────────────────────────


class TestAlgorithmRestriction:
    """RS256 validator MUST reject HS256/none tokens BEFORE signature verification."""

    def setup_method(self) -> None:
        # RS256 mode with JWKS URL — algorithm check fires before any key lookup
        self.validator = TokenValidator(
            jwt_algorithm="RS256",
            jwks_url="https://cognito.example.com/.well-known/jwks.json",
        )

    def test_hs256_token_rejected_with_401(self) -> None:
        """HS256-signed token must be rejected when validator is in RS256 mode."""
        token = _hs_token(_base_payload())
        result = self.validator.validate(token)
        assert result is None

    def test_none_algorithm_rejected(self) -> None:
        """'none' algorithm token must be rejected."""
        # Build manually — PyJWT won't encode 'none' normally.
        # Serialize payload with int timestamps (json.dumps can't handle datetime).
        import base64

        raw = _base_payload()
        serializable = {
            k: int(v.timestamp()) if isinstance(v, datetime) else v
            for k, v in raw.items()
        }
        h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(
            json.dumps(serializable).encode()
        ).rstrip(b"=").decode()
        none_token = f"{h}.{p}."
        result = self.validator.validate(none_token)
        assert result is None

    def test_hs256_rejected_before_jwks_fetch(self) -> None:
        """JWKS endpoint must NOT be called when algorithm is HS256 (rejected early)."""
        token = _hs_token(_base_payload())
        with patch("httpx.Client") as mock_client:
            self.validator.validate(token)
            mock_client.assert_not_called()

    def test_hs384_rejected(self) -> None:
        token = jwt.encode(_base_payload(), HS_SECRET, algorithm="HS384")
        assert self.validator.validate(token) is None

    def test_hs512_rejected(self) -> None:
        token = jwt.encode(_base_payload(), HS_SECRET, algorithm="HS512")
        assert self.validator.validate(token) is None


# ── RS256 JWKS validation ─────────────────────────────────────────────────────


class TestRS256JWKSValidation:
    def _make_validator(self) -> TokenValidator:
        v = TokenValidator(
            jwt_algorithm="RS256",
            jwks_url="https://cognito.example.com/.well-known/jwks.json",
        )
        # Pre-populate cache so no HTTP call needed
        from jwt.algorithms import RSAAlgorithm

        v._jwks_cache = {_KID: RSAAlgorithm.from_jwk(
            json.loads(RSAAlgorithm.to_jwk(_RSA_PUBLIC_KEY))
        )}
        v._jwks_cache_ts = time.monotonic()
        return v

    def test_valid_rs256_token_returns_payload(self) -> None:
        validator = self._make_validator()
        token = _rs256_token(_base_payload())
        result = validator.validate(token)
        assert result is not None
        assert result.sub == "user-123"

    def test_expired_rs256_token_returns_none(self) -> None:
        validator = self._make_validator()
        token = _rs256_token(
            _base_payload(exp=datetime.now(tz=timezone.utc) - timedelta(hours=1))
        )
        assert validator.validate(token) is None

    def test_wrong_key_returns_none(self) -> None:
        """Token signed with a different private key must be rejected."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(_base_payload(), other_pem, algorithm="RS256", headers={"kid": _KID})
        validator = self._make_validator()
        assert validator.validate(token) is None

    def test_unknown_kid_triggers_jwks_refresh(self) -> None:
        """When kid is not in cache, validator must fetch JWKS to find the key."""
        validator = TokenValidator(
            jwt_algorithm="RS256",
            jwks_url="https://cognito.example.com/.well-known/jwks.json",
        )
        token = _rs256_token(_base_payload(), kid="new-kid")

        # Generate a new key pair for "new-kid"
        new_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        new_public = new_private.public_key()
        new_pem = new_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(_base_payload(), new_pem, algorithm="RS256", headers={"kid": "new-kid"})

        jwks = _make_jwks_response(new_public, kid="new-kid")
        mock_resp = MagicMock()
        mock_resp.json.return_value = jwks
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
            result = validator.validate(token)

        assert result is not None
        assert result.sub == "user-123"

    def test_jwks_cache_expires_after_ttl(self) -> None:
        """Cache older than 1 hour must trigger a refresh."""
        validator = self._make_validator()
        # Backdate cache timestamp beyond TTL
        validator._jwks_cache_ts = time.monotonic() - 3601

        jwks = _make_jwks_response()
        mock_resp = MagicMock()
        mock_resp.json.return_value = jwks
        mock_resp.raise_for_status = MagicMock()

        token = _rs256_token(_base_payload())
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
            result = validator.validate(token)

        assert result is not None

    def test_missing_required_claims_rejected(self) -> None:
        """Tokens missing sub, exp, or iat must be rejected."""
        validator = self._make_validator()
        # Token without 'iat'
        payload = {
            "sub": "user-123",
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1),
            # iat intentionally missing
        }
        token = _rs256_token(payload)
        assert validator.validate(token) is None
