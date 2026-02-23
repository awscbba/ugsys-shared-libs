"""
Reusable FastAPI auth middleware and dependency injection helpers.
Drop this into any ugsys service to get JWT auth with zero boilerplate.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import TokenPayload
from .token_validator import TokenValidator

_bearer = HTTPBearer(auto_error=False)


def make_auth_dependency(validator: TokenValidator):
    """
    Factory that creates a FastAPI dependency bound to a specific TokenValidator.

    Usage:
        validator = TokenValidator(jwt_secret=settings.jwt_secret)
        get_current_user = make_auth_dependency(validator)

        @router.get("/me")
        async def me(user: Annotated[TokenPayload, Depends(get_current_user)]):
            ...
    """

    async def _get_current_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> TokenPayload:
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
            )
        payload = validator.validate(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        if payload.type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token type must be 'access'",
            )
        return payload

    return _get_current_user


def require_roles(*roles: str):
    """
    Dependency factory that enforces role-based access.

    Usage:
        @router.delete("/users/{id}")
        async def delete_user(
            user: Annotated[TokenPayload, Depends(require_roles("admin"))]
        ):
            ...
    """

    async def _check_roles(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    ) -> TokenPayload:
        # Re-use the base validator — services inject their own via app state
        raise NotImplementedError(
            "Use make_auth_dependency() and check roles manually, "
            "or wire require_roles with a validator instance."
        )

    return _check_roles


# Convenience aliases — services override these via app.state or DI
async def get_current_user(request: Request) -> TokenPayload:
    """
    Generic dependency. Services must set request.app.state.token_validator
    with a configured TokenValidator instance.
    """
    validator: TokenValidator = getattr(request.app.state, "token_validator", None)
    if not validator:
        raise RuntimeError("token_validator not configured on app.state")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    token = auth_header.removeprefix("Bearer ").strip()
    payload = validator.validate(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload


async def require_auth(request: Request) -> TokenPayload:
    """Alias for get_current_user — more explicit name for route dependencies."""
    return await get_current_user(request)


class AuthMiddleware:
    """
    ASGI middleware that attaches the decoded token payload to request.state.user.
    Does NOT block unauthenticated requests — use Depends(require_auth) for that.
    """

    def __init__(self, app, validator: TokenValidator):
        self.app = app
        self.validator = validator

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            if auth.startswith("Bearer "):
                token = auth.removeprefix("Bearer ").strip()
                payload = self.validator.validate(token)
                scope.setdefault("state", {})["user"] = payload
        await self.app(scope, receive, send)
