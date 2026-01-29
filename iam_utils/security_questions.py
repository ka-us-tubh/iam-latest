import re

from .security import get_password_hash, verify_password


_WHITESPACE_RE = re.compile(r"\s+")


def normalize_security_answer(answer: str) -> str:
    """Normalize a security-question answer for consistent hashing/verification."""

    if answer is None:
        raise ValueError("answer must be a non-empty string")

    if not isinstance(answer, str):
        answer = str(answer)

    normalized = _WHITESPACE_RE.sub(" ", answer.strip().lower())
    if not normalized:
        raise ValueError("answer must be a non-empty string")

    return normalized


def hash_security_answer(answer: str) -> str:
    """Hash a security-question answer for storage."""

    normalized = normalize_security_answer(answer)
    return get_password_hash(normalized)


def verify_security_answer(answer: str, answer_hash: str) -> bool:
    """Verify a presented security-question answer against a stored hash."""

    try:
        normalized = normalize_security_answer(answer)
    except ValueError:
        return False

    return verify_password(normalized, answer_hash)
