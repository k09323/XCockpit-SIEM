from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.config import settings
from backend.core.database import (
    get_conn,
    get_session_hours,
    get_system_setting,
    set_system_setting,
)
from backend.dependencies import require_auth

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


def _make_access_token(user_id: str, username: str, role: str) -> str:
    # Access token TTL = configured session_hours (admin-editable, default 24h)
    hours = get_session_hours()
    exp = datetime.now(timezone.utc) + timedelta(hours=hours)
    return jwt.encode(
        {"sub": user_id, "username": username, "role": role, "exp": exp},
        settings.auth.secret_key,
        algorithm="HS256",
    )


def _make_refresh_token(user_id: str) -> str:
    # Refresh token TTL = max(7 days, session_hours) so it never expires
    # before the access token. Admin can extend session beyond 7 days; the
    # refresh token will keep up.
    hours = max(get_session_hours(), settings.auth.refresh_token_expire_days * 24)
    exp = datetime.now(timezone.utc) + timedelta(hours=hours)
    token = jwt.encode(
        {"sub": user_id, "type": "refresh", "exp": exp},
        settings.auth.secret_key,
        algorithm="HS256",
    )
    # Store hash in DB
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    get_conn().execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        [token_hash, user_id, exp.replace(tzinfo=None)],
    )
    return token


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        [body.username],
    ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_id, username, pw_hash, role = row
    if not bcrypt.checkpw(body.password.encode(), pw_hash.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    conn.execute("UPDATE users SET last_login = now() WHERE id = ?", [user_id])
    return TokenResponse(
        access_token=_make_access_token(user_id, username, role),
        refresh_token=_make_refresh_token(user_id),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest) -> TokenResponse:
    try:
        payload = jwt.decode(body.refresh_token, settings.auth.secret_key, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    conn = get_conn()
    row = conn.execute(
        "SELECT user_id FROM refresh_tokens WHERE token_hash = ? AND expires_at > now()",
        [token_hash],
    ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or expired")

    user_id = row[0]
    user_row = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?", [user_id]
    ).fetchone()
    if not user_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    _, username, role = user_row
    return TokenResponse(
        access_token=_make_access_token(user_id, username, role),
        refresh_token=_make_refresh_token(user_id),
    )


@router.post("/logout")
def logout(body: RefreshRequest, _=Depends(require_auth)) -> dict:
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    get_conn().execute("DELETE FROM refresh_tokens WHERE token_hash = ?", [token_hash])
    return {"detail": "Logged out"}


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.put("/password")
def change_password(body: ChangePasswordRequest, payload: dict = Depends(require_auth)) -> dict:
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    conn = get_conn()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE id = ?", [payload["sub"]]
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if not bcrypt.checkpw(body.current_password.encode(), row[0].encode()):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    new_hash = bcrypt.hashpw(body.new_password.encode(), bcrypt.gensalt()).decode()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", [new_hash, payload["sub"]])
    # Revoke all refresh tokens for this user
    conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", [payload["sub"]])
    return {"detail": "Password changed. Please log in again."}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


def _require_admin(payload: dict = Depends(require_auth)) -> dict:
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload


@router.get("/users")
def list_users(_=Depends(_require_admin)) -> list:
    rows = get_conn().execute(
        "SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at"
    ).fetchall()
    return [
        {
            "id": r[0], "username": r[1], "role": r[2],
            "created_at": r[3].isoformat() if r[3] else None,
            "last_login": r[4].isoformat() if r[4] else None,
        }
        for r in rows
    ]


@router.post("/users", status_code=201)
def create_user(body: CreateUserRequest, _=Depends(_require_admin)) -> dict:
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be admin / analyst / viewer")
    conn = get_conn()
    if conn.execute("SELECT COUNT(*) FROM users WHERE username = ?", [body.username]).fetchone()[0]:
        raise HTTPException(status_code=409, detail="Username already exists")
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    row = conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) RETURNING id",
        [body.username, pw_hash, body.role],
    ).fetchone()
    return {"id": row[0], "username": body.username, "role": body.role}


@router.delete("/users/{user_id}")
def delete_user(user_id: str, payload: dict = Depends(_require_admin)) -> dict:
    if user_id == payload["sub"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    conn = get_conn()
    if not conn.execute("SELECT COUNT(*) FROM users WHERE id = ?", [user_id]).fetchone()[0]:
        raise HTTPException(status_code=404, detail="User not found")
    conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", [user_id])
    conn.execute("DELETE FROM users WHERE id = ?", [user_id])
    return {"detail": "User deleted"}


# ---------------------------------------------------------------------------
# System settings (admin only) — currently exposes session_hours
# ---------------------------------------------------------------------------

class SessionSettingsRequest(BaseModel):
    session_hours: int


@router.get("/system-settings")
def read_system_settings(_=Depends(_require_admin)) -> dict:
    return {
        "session_hours": get_session_hours(),
        "session_hours_min": 1,
        "session_hours_max": 24 * 30,  # 30 days
    }


@router.put("/system-settings")
def update_system_settings(
    body: SessionSettingsRequest, _=Depends(_require_admin)
) -> dict:
    if body.session_hours < 1 or body.session_hours > 24 * 30:
        raise HTTPException(
            status_code=400,
            detail="session_hours must be between 1 and 720 (30 days)",
        )
    set_system_setting("session_hours", body.session_hours)
    return {
        "detail": "Session settings updated. New value applies to future logins.",
        "session_hours": get_session_hours(),
    }
