from typing import Dict, Iterable, Mapping, Optional, Set

from .tokens import (
    AuthError,
    TokenError,
    verify_csrf_token,
)


class CSRFError(AuthError):
    """Raised when CSRF validation fails."""


def validate_csrf_request(
    method: str,
    header_token: Optional[str],
    cookie_token: Optional[str],
    *,
    safe_methods: Iterable[str] = ("GET", "HEAD", "OPTIONS", "TRACE"),
) -> Optional[str]:
    """Validate CSRF tokens for a request in a stack-independent way.

    Args:
        method: HTTP method of the request (e.g. "GET", "POST").
        header_token: CSRF token provided in a header (e.g. "X-CSRF-Token").
        cookie_token: CSRF token provided in a cookie.
        safe_methods: HTTP methods that are exempt from CSRF checks.

    Returns:
        The CSRF subject (string) if validation succeeds, or ``None`` for
        safe methods where no CSRF protection is enforced.

    Raises:
        CSRFError: If tokens are missing, mismatched, or invalid.
    """

    safe: Set[str] = {m.upper() for m in safe_methods}
    if method.upper() in safe:
        # No CSRF validation required for safe methods
        return None

    if not header_token or not cookie_token:
        raise CSRFError("CSRF token missing")

    if header_token != cookie_token:
        raise CSRFError("CSRF token mismatch")

    try:
        subject = verify_csrf_token(header_token)
    except TokenError:
        # Any token-format related issues are treated as CSRF failures.
        raise CSRFError("Invalid CSRF token") from None

    return subject


class OriginError(AuthError):
    """Raised when an HTTP Origin header fails validation."""


def validate_origin(
    origin: Optional[str],
    allowed_origins: Iterable[str],
    *,
    allow_null_origin: bool = False,
) -> Optional[str]:
    """Validate an Origin header value in a stack-independent way.

    If ``"*"`` is present in ``allowed_origins``, any non-empty origin is
    accepted. Otherwise, the origin must match one of the entries exactly.
    """

    if not origin:
        if allow_null_origin:
            return None
        raise OriginError("Origin header missing")

    allowed_set = set(allowed_origins)
    if "*" in allowed_set:
        return origin

    if origin not in allowed_set:
        raise OriginError("Origin not allowed")

    return origin


def apply_security_headers(
    headers: Optional[Mapping[str, str]] = None,
    *,
    content_security_policy: Optional[str] = None,
    frame_options: str = "DENY",
    content_type_options: str = "nosniff",
    referrer_policy: str = "no-referrer",
    hsts_max_age: Optional[int] = None,
    hsts_include_subdomains: bool = True,
    hsts_preload: bool = False,
) -> Dict[str, str]:
    """Apply common security headers to a headers mapping.

    This helper is framework-agnostic: pass in your existing response
    headers (or ``None``) and use the returned dict when building the
    final response in your web framework of choice.
    """

    result: Dict[str, str] = dict(headers or {})

    if frame_options and "X-Frame-Options" not in result:
        result["X-Frame-Options"] = frame_options

    if content_type_options and "X-Content-Type-Options" not in result:
        result["X-Content-Type-Options"] = content_type_options

    if referrer_policy and "Referrer-Policy" not in result:
        result["Referrer-Policy"] = referrer_policy

    if content_security_policy and "Content-Security-Policy" not in result:
        result["Content-Security-Policy"] = content_security_policy

    if hsts_max_age is not None and "Strict-Transport-Security" not in result:
        parts = [f"max-age={hsts_max_age}"]
        if hsts_include_subdomains:
            parts.append("includeSubDomains")
        if hsts_preload:
            parts.append("preload")
        result["Strict-Transport-Security"] = "; ".join(parts)

    return result
