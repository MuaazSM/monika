"""JWT issuance and password hashing for the demo API.

Deliberately weak: unsalted SHA-256 password hashes (CLAUDE.md rule 10). Do not
'improve' this to bcrypt/argon2 — a leaked password_hash being crackable is part of
the DATA_EXPOSURE story.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from .settings import JWT_ALG, JWT_SECRET


def hash_password(password: str) -> str:
    """Unsalted SHA-256 — intentionally weak."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-timeness deliberately not a concern here."""
    return hash_password(password) == password_hash


def issue_token(sub: int, role: str, ttl_minutes: int) -> str:
    """HS256 token with sub, jti, role, exp. Secret shared with monika."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": sub,
        "jti": str(uuid.uuid4()),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict[str, Any]:
    """Decode/verify a bearer token; raises jwt exceptions on failure.

    `verify_sub=False`: the PRD requires an integer `sub` (user id), but pyjwt>=2.10
    enforces RFC 7519's string-`sub` rule. The spec wins — monika decodes the same way.
    """
    return jwt.decode(
        token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_sub": False}
    )
