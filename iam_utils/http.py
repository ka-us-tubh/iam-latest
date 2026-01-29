from typing import Mapping, Optional


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Extract a Bearer token from an Authorization header value.

    Returns None if the header is missing or does not contain a Bearer token.
    """

    if not authorization_header or not isinstance(authorization_header, str):
        return None

    value = authorization_header.strip()
    parts = value.split()
    if len(parts) != 2:
        return None

    scheme, token = parts[0], parts[1]
    if scheme.lower() != "bearer":
        return None

    token = token.strip()
    if not token:
        return None

    return token


def get_token_from_headers(
    headers: Mapping[str, str],
    *,
    header_name: str = "Authorization",
) -> Optional[str]:
    """Get an access token from a headers mapping (case-insensitive)."""

    if not headers:
        return None

    target = header_name.lower()
    value: Optional[str] = None
    for k, v in headers.items():
        if str(k).lower() == target:
            value = v
            break

    return extract_bearer_token(value)


class BearerTokenError(Exception):
    pass


def require_bearer_token(
    headers: Mapping[str, str],
    *,
    header_name: str = "Authorization",
) -> str:
    token = get_token_from_headers(headers, header_name=header_name)
    if token is None:
        raise BearerTokenError(f"Missing or invalid {header_name} Bearer token")
    return token


def get_token_from_cookies(
    cookies: Mapping[str, str],
    *,
    cookie_name: str = "access_token",
) -> Optional[str]:
    """Get a token from a cookies mapping."""

    if not cookies:
        return None

    try:
        value = cookies.get(cookie_name)
    except AttributeError:
        value = None

    if not value:
        return None

    value = str(value).strip()
    if not value:
        return None

    return value
