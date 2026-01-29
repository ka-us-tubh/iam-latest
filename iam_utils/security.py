import hmac
import secrets
from typing import Any, Optional, Tuple
from passlib.context import CryptContext

from .config import iam_config


_PWD_CONTEXT: Optional[CryptContext] = None
_PWD_CONTEXT_SETTINGS: Optional[Tuple[Tuple[str, ...], str]] = None


def _get_pwd_context() -> CryptContext:
    global _PWD_CONTEXT
    global _PWD_CONTEXT_SETTINGS

    schemes = tuple(iam_config.PASSWORD_SCHEMES)
    deprecated = iam_config.PASSWORD_DEPRECATED
    settings = (schemes, deprecated)

    if _PWD_CONTEXT is None or _PWD_CONTEXT_SETTINGS != settings:
        _PWD_CONTEXT = CryptContext(
            schemes=list(schemes),
            deprecated=deprecated,
        )
        _PWD_CONTEXT_SETTINGS = settings
    return _PWD_CONTEXT


def get_password_hash(password: str) -> str:
    return _get_pwd_context().hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return _get_pwd_context().verify(plain_password, hashed_password)


def generate_random_token(n_bytes: int = 32) -> str:
    """Generate a URL-safe random token.

    Useful for non-JWT tokens such as invitation codes, non-persistent
    CSRF secrets, etc.
    """

    return secrets.token_urlsafe(n_bytes)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to avoid timing attacks."""

    # hmac.compare_digest handles different types/lengths safely.
    return hmac.compare_digest(val1, val2)


def __getattr__(name: str) -> Any:
    if name in {"SECRET_KEY", "ALGORITHM", "ACCESS_TOKEN_EXPIRE_MINUTES"}:
        return getattr(iam_config, name)
    raise AttributeError(name)
