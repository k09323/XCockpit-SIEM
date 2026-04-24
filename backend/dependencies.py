from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from backend.config import settings


def _extract_token(request: Request) -> str | None:
    """Accept both 'Bearer <token>' and 'Token <token>' schemes."""
    auth = request.headers.get("Authorization", "")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() in ("bearer", "token"):
        return parts[1]
    return None


def require_auth(request: Request) -> dict:
    token = _extract_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Token"},
        )
    try:
        payload = jwt.decode(
            token,
            settings.auth.secret_key,
            algorithms=["HS256"],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
