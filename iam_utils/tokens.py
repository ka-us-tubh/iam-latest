from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

import jwt

from .config import iam_config


_JWT_REGEX = re.compile(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$")


class AuthError(Exception):
    """Base class for authentication-related errors."""


class TokenError(AuthError):
    """Base class for token-related errors."""


class TokenFormatError(TokenError, ValueError):
    """Raised when a token has an invalid format."""


class InvalidSubjectError(TokenError, ValueError):
    """Raised when a token subject is missing or invalid."""


class CredentialsError(TokenError, ValueError):
    """Raised when credentials/token verification fails."""


def create_access_token(
    *,
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=iam_config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, iam_config.SECRET_KEY, algorithm=iam_config.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = jwt.decode(
        token,
        iam_config.SECRET_KEY,
        algorithms=[iam_config.ALGORITHM],
    )
    return payload


def _verify_and_decode(token: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str):
        raise TokenFormatError("Token must be a non-empty string")

    if not _JWT_REGEX.match(token):
        raise TokenFormatError("Token format is invalid - expected JWT format")

    try:
        return decode_access_token(token)
    except jwt.PyJWTError:
        return None


def create_subject_token(
    subject: str,
    *,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a JWT access token for an arbitrary subject (user id, email, etc.)."""
    if not subject or not isinstance(subject, str):
        raise InvalidSubjectError("subject must be a non-empty string")

    now = datetime.now(timezone.utc)
    claims: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "jti": secrets.token_urlsafe(32),
    }
    if additional_claims:
        for key, value in additional_claims.items():
            if key in {"sub", "iat", "jti"}:
                continue
            claims[key] = value

    token = create_access_token(data=claims, expires_delta=expires_delta)
    return token


def verify_token(token: str) -> str:
    """Verify a JWT token and return the subject (sub) if valid.

    Raises:
        TokenFormatError: If the token format is invalid.
        CredentialsError: If the token cannot be decoded, is expired/invalid, or has no subject.
    """
    payload = _verify_and_decode(token)
    if payload is None:
        raise CredentialsError("Token is invalid or expired")

    subject = payload.get("sub")
    if subject is None:
        raise CredentialsError("Token subject is missing")
    return str(subject)


def _create_flagged_token(
    subject: str,
    claim_key: str,
    *,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    claims: Dict[str, Any] = dict(additional_claims or {})
    claims[claim_key] = True
    return create_subject_token(
        subject=subject,
        expires_delta=expires_delta,
        additional_claims=claims,
    )


def _verify_flagged_token(token: str, claim_key: str) -> str:
    payload = _verify_and_decode(token)
    if payload is None:
        raise CredentialsError("Token is invalid or expired")

    if not payload.get(claim_key):
        raise CredentialsError(f"Token is not a valid {claim_key} token")

    subject = payload.get("sub")
    if subject is None:
        raise CredentialsError("Token subject is missing")
    return str(subject)


def create_csrf_token(
    subject: str,
    *,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    return _create_flagged_token(
        subject=subject,
        claim_key="csrf",
        expires_delta=expires_delta,
        additional_claims=additional_claims,
    )


def verify_csrf_token(token: str) -> str:
    return _verify_flagged_token(token, claim_key="csrf")


def create_refresh_token(
    subject: str,
    *,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    return _create_flagged_token(
        subject=subject,
        claim_key="refresh",
        expires_delta=expires_delta,
        additional_claims=additional_claims,
    )


def verify_refresh_token(token: str) -> str:
    return _verify_flagged_token(token, claim_key="refresh")


def create_token_pair(
    subject: str,
    *,
    access_expires: Optional[timedelta] = None,
    refresh_expires: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    access_token = create_subject_token(
        subject=subject,
        expires_delta=access_expires,
        additional_claims=additional_claims,
    )
    refresh_token = create_refresh_token(
        subject=subject,
        expires_delta=refresh_expires,
        additional_claims=additional_claims,
    )
    return {"access_token": access_token, "refresh_token": refresh_token}


def rotate_refresh_token(
    refresh_token: str,
    *,
    access_expires: Optional[timedelta] = None,
    refresh_expires: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    try:
        subject = verify_refresh_token(refresh_token)
    except TokenError:
        return None
    return create_token_pair(
        subject=subject,
        access_expires=access_expires,
        refresh_expires=refresh_expires,
        additional_claims=additional_claims,
    )


def get_token_claim(token: str, claim: str) -> Optional[Any]:
    """Best-effort read of a claim from a JWT.

    Returns None if the token cannot be decoded.
    """

    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        return None

    return payload.get(claim)


def get_token_jti(token: str) -> Optional[str]:
    jti = get_token_claim(token, "jti")
    if jti is None:
        return None
    return str(jti)


def get_token_exp(token: str) -> Optional[datetime]:
    """Return the exp claim as a timezone-aware datetime, if present."""

    exp = get_token_claim(token, "exp")
    if exp is None:
        return None

    try:
        ts = float(exp)
    except (TypeError, ValueError):
        return None

    return datetime.fromtimestamp(ts, tz=timezone.utc)


def verify_token_not_revoked(
    token: str,
    *,
    is_jti_revoked: Optional[Callable[[str], bool]] = None,
) -> Optional[str]:
    """Verify a token and ensure its JTI is not revoked.

    This is storage-agnostic: you provide an ``is_jti_revoked`` callback.

    Returns the token subject if valid and not revoked, otherwise None.
    """

    try:
        subject = verify_token(token)
    except TokenError:
        return None

    jti = get_token_jti(token)
    if not jti:
        return subject

    if is_jti_revoked is None:
        return subject

    try:
        if is_jti_revoked(jti):
            return None
    except Exception:
        return None

    return subject


def consume_one_time_token(
    token: str,
    *,
    is_jti_used: Callable[[str], bool],
    mark_jti_used: Callable[[str, Optional[datetime]], None],
    require_jti: bool = True,
) -> Optional[str]:
    """Consume a token exactly once, using its JTI.

    Typical use: password reset tokens, email verification tokens.

    Storage is provided by the caller via callbacks.
    """

    try:
        subject = verify_token(token)
    except TokenError:
        return None

    jti = get_token_jti(token)
    if not jti:
        return None if require_jti else subject

    try:
        if is_jti_used(jti):
            return None
    except Exception:
        return None

    expires_at = get_token_exp(token)
    try:
        mark_jti_used(jti, expires_at)
    except Exception:
        return None

    return subject
