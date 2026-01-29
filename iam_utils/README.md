# iam_utils

Stack-independent IAM helpers with a practical FastAPI integration story.

This package stays **framework-agnostic**, but the examples below show how you can plug it into a FastAPI backend for:

- **Authentication** (login / refresh / logout)
- **Authorization** (current user dependency, role/permission checks)
- **User management** (signup hash/verify, active/superuser checks)
- **Optional security-question verification** (route helper)

---

## Features / functionality provided

### Tokens (JWT)

- **Access token helpers**
  - `create_access_token`, `decode_access_token`
  - `create_subject_token` (convenience for `sub`-based access tokens)
  - `verify_token` (returns subject) and raises `CredentialsError` on invalid/expired tokens
- **Refresh tokens / session rotation**
  - `create_refresh_token`, `verify_refresh_token`
  - `create_token_pair` (access+refresh)
  - `rotate_refresh_token` (rotate refresh and mint a fresh access)
  - `refresh_session` (storage-agnostic refresh handler)
- **CSRF tokens**
  - `create_csrf_token`, `verify_csrf_token`
- **Token metadata & revocation utilities**
  - `get_token_jti`, `get_token_exp`
  - `verify_token_not_revoked` (requires `is_jti_revoked` callback)
  - `consume_one_time_token` (one-time use via JTI; requires `is_jti_used` + `mark_jti_used` callbacks)

### Authentication / authorization (storage-agnostic helpers)

- **Authenticate & sign-in flows**
  - `authenticate_user` (username/email + password)
  - `login_user` (returns token pair)
  - `logout_session` (optional JTI revocation)
  - `can_sign_up_user` (checks email availability via callback)
- **User loading from access token**
  - `get_user_from_access_token`, `require_user_from_access_token`
  - `validate_user` (active/superuser/permission checks)
- **User checks & enforcement helpers**
  - `ensure_user_is_active`, `ensure_user_is_superuser`
  - `ensure_user_has_permissions`, `ensure_user_has_any_permission`, `user_has_permissions`
  - `ensure_user_has_effective_permissions` (roles -> permissions)
  - `get_user_roles`
- **Security question challenge helper**
  - `verify_security_question_challenge`

### Cookie-based session wiring

- **Set auth cookies**
  - `build_auth_cookie_specs` (cookie options for access+refresh)
  - `apply_auth_cookie_specs`
- **Delete auth cookies**
  - `build_auth_cookie_delete_specs`
  - `apply_auth_cookie_delete_specs`

### HTTP token extraction helpers

- **Bearer tokens**
  - `extract_bearer_token`, `require_bearer_token` (raises `BearerTokenError`)
- **Cookie/header parsing**
  - `get_token_from_headers`, `get_token_from_cookies`

### RBAC utilities (roles & permissions)

- `expand_permissions` (role -> permissions mapping)
- `user_effective_permissions` (direct + role-derived)
- `user_has_effective_permissions`

### Password hashing & verification

- `get_password_hash`, `verify_password`
- Configurable via `iam_utils.config.iam_config` (e.g. `IAM_PASSWORD_SCHEMES`)

### General security utilities

- **Random tokens / constant-time compare**
  - `generate_random_token`, `constant_time_compare`

### Security questions (normalize / hash / verify)

- `normalize_security_answer`, `hash_security_answer`, `verify_security_answer`

### Sanitization utilities

- `sanitize_string`, `sanitize_email`, `sanitize_dict`, `sanitize_list`
- `strip_html_tags`, `normalize_whitespace`, `sanitize_url`
- `validate_password_strength`

### Middleware-style helpers (framework-agnostic)

- **CSRF validation (double-submit pattern)**
  - `validate_csrf_request` (raises `CSRFError`)
- **Origin validation**
  - `validate_origin` (raises `OriginError`)
- **Security headers**
  - `apply_security_headers`

### Exceptions

- **Token/auth errors**
  - `AuthError`, `TokenError`, `CredentialsError`, `TokenFormatError`, `InvalidSubjectError`
- **Authorization errors**
  - `InactiveUserError`, `PermissionDeniedError`

### Public submodules

- `iam_utils.auth`, `iam_utils.tokens`, `iam_utils.security`, `iam_utils.security_questions`
- `iam_utils.http`, `iam_utils.middleware`, `iam_utils.rbac`, `iam_utils.sanitization`, `iam_utils.config`

---

## Quick start (FastAPI integration)

### 1) Configure secrets at startup

`iam_utils` reads security settings from `iam_utils.config.iam_config`.

```python
from iam_utils.config import iam_config


def configure_iam() -> None:
    # In production, load from env (IAM_SECRET_KEY, IAM_ALGORITHM, ...)
    iam_config.load_from_env()

    # Or set directly (DON'T hardcode in real deployments)
    # iam_config.SECRET_KEY = "..."
    # iam_config.ALGORITHM = "HS256"
```

Minimal FastAPI wiring:

```python
from fastapi import FastAPI


app = FastAPI()


@app.on_event("startup")
def _startup() -> None:
    configure_iam()


# Later:
# app.include_router(router)  # the routers shown below
```

Minimal runnable structure (recommended):

```text
your_app/
  main.py
  auth_routes.py
```

`main.py`

```python
from fastapi import FastAPI

from .auth_routes import router as auth_router
from iam_utils.config import iam_config


def configure_iam() -> None:
    iam_config.load_from_env()


app = FastAPI()


@app.on_event("startup")
def _startup() -> None:
    configure_iam()


app.include_router(auth_router)
```

### 2) Your user model / storage assumptions

The auth helpers are storage-agnostic:

- You provide lookup callbacks like `get_user_by_username(db, username)` / `get_user_by_email(db, email)`.
- Password verification reads a configurable attribute (default: `hashed_password`).

If your existing user table uses different attribute/column names, use `UserSchema`:

```python
from iam_utils.auth import UserSchema


user_schema = UserSchema(
    hashed_password_attr="pwd_hash",
    is_active_attr="active_flag",
    is_superuser_attr="admin_flag",
    username_attr="login_name",
    email_attr="email_addr",
    id_attr="user_id",
    subject_getter=lambda u: str(u.user_id),
)
```

Missing optional attributes like `roles`, `permissions`, `is_active`, and `is_superuser` do not break the library as long as you don't request those checks.

### 3) Auth routes (login / refresh / logout)

This shows a cookie-based session style:

- Access token cookie: `access_token`
- Refresh token cookie: `refresh_token`

The refresh/logout endpoints below read tokens from cookies via `Request`.

Security notes for cookie-based auth:

- Always serve over **HTTPS** in production so `Secure` cookies are actually protected.
- Consider scoping the refresh cookie to a narrower path (e.g. `/auth/refresh`) to reduce exposure.
- For state-changing endpoints, use a CSRF strategy (see the CSRF section below).

```python
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from iam_utils.auth import (
    apply_auth_cookie_specs,
    build_auth_cookie_specs,
    apply_auth_cookie_delete_specs,
    build_auth_cookie_delete_specs,
    login_user,
    logout_session,
    refresh_session,
)
from iam_utils.security import get_password_hash, verify_password
from iam_utils.security_questions import hash_security_answer
from iam_utils.sanitization import validate_password_strength


router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str


class SignUpIn(BaseModel):
    username: str
    email: str
    password: str
    security_answer: str | None = None


def get_db():
    ...


def get_user_by_username(db, username: str):
    ...


def get_user_by_email(db, email: str):
    ...


def revoke_jti(jti: str, expires_at):
    # Store revoked JTI in your DB/redis with TTL until expires_at
    ...


def is_jti_revoked(jti: str) -> bool:
    ...


@router.post("/login")
def login(payload: LoginIn, response: Response, db=Depends(get_db)):
    if not payload.username and not payload.email:
        raise HTTPException(status_code=422, detail="username or email is required")

    tokens = login_user(
        db=db,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        get_user_by_username=get_user_by_username,
        get_user_by_email=get_user_by_email,
        verify_password_fn=verify_password,
    )
    if tokens is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    specs = build_auth_cookie_specs(
        tokens,
        secure=True,
        samesite="lax",
        refresh_path="/auth/refresh",
        set_max_age_from_exp=True,
    )
    apply_auth_cookie_specs(response.set_cookie, specs)
    return {"ok": True}


@router.post("/refresh")
def refresh(request: Request, response: Response, db=Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    # If you store refresh token JTIs in a denylist, pass is_jti_revoked + revoke_jti
    new_tokens = refresh_session(
        refresh_token,
        is_jti_revoked=is_jti_revoked,
        revoke_jti=revoke_jti,
    )
    if new_tokens is None:
        raise HTTPException(status_code=401, detail="Invalid refresh")

    specs = build_auth_cookie_specs(
        new_tokens,
        secure=True,
        samesite="lax",
        refresh_path="/auth/refresh",
        set_max_age_from_exp=True,
    )
    apply_auth_cookie_specs(response.set_cookie, specs)
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, response: Response):
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    # Optional: revoke JTIs so tokens can't be reused
    logout_session(
        revoke_jti=revoke_jti,
        access_token=access_token,
        refresh_token=refresh_token,
    )

    delete_specs = build_auth_cookie_delete_specs(
        refresh_path="/auth/refresh",
    )
    apply_auth_cookie_delete_specs(response.delete_cookie, delete_specs)
    return {"ok": True}


@router.post("/signup")
def signup(payload: SignUpIn, db=Depends(get_db)):
    validate_password_strength(payload.password)

    password_hash = get_password_hash(payload.password)

    security_answer_hash = None
    if payload.security_answer:
        security_answer_hash = hash_security_answer(payload.security_answer)

    # Create user in your DB (example fields)
    # db.users.create(
    #   username=payload.username,
    #   email=payload.email,
    #   hashed_password=password_hash,
    #   security_answer_hash=security_answer_hash,
    # )
    ...

    return {"ok": True}
```

Notes:

- `login_user` is **username-first**, but you can pass `email=...` with `get_user_by_email` too.
- Token verification functions like `verify_token` and `verify_refresh_token` **raise `CredentialsError`** when invalid.
- If you don't use token revocation/denylists, you can omit `is_jti_revoked`/`revoke_jti`.

---

## Current user dependency (authorization)

Recommended approach: use `iam_utils.http` to extract tokens, then `iam_utils.auth.require_user_from_access_token()` to verify + load the user.

```python
from fastapi import Depends, HTTPException, Request

from iam_utils.http import get_token_from_cookies, get_token_from_headers
from iam_utils.tokens import CredentialsError
from iam_utils.auth import require_user_from_access_token


def get_db():
    ...


def get_user_by_subject(db, subject: str):
    # If your `sub` is username -> lookup by username.
    # If your `sub` is email -> lookup by email.
    ...


def get_current_user(request: Request, db=Depends(get_db)):
    token = get_token_from_cookies(request.cookies, cookie_name="access_token")
    if not token:
        token = get_token_from_headers(request.headers, header_name="Authorization")

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        user = require_user_from_access_token(
            token,
            db=db,
            get_user_by_subject=get_user_by_subject,
            # Optional if you store JTIs in a denylist:
            # is_jti_revoked=is_jti_revoked,
        )
    except CredentialsError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user
```

### Permission and role checks

```python
from fastapi import Depends

from iam_utils.auth import ensure_user_has_effective_permissions


ROLE_TO_PERMS = {
    "admin": ["read", "write", "manage_users"],
    "user": ["read"],
}


def require_permission(permission: str):
    def dep(user=Depends(get_current_user)):
        ensure_user_has_effective_permissions(
            user,
            [permission],
            role_to_permissions=ROLE_TO_PERMS,
        )
        return user

    return dep
```

---

## Optional: security-question route helper

If you store a hashed security answer on the user, you can validate a challenge without duplicating hashing logic.

```python
from fastapi import HTTPException
from pydantic import BaseModel

from iam_utils.auth import verify_security_question_challenge


class SecurityQuestionIn(BaseModel):
    username: str
    answer: str


@router.post("/security-question")
def security_question(payload: SecurityQuestionIn, db=Depends(get_db)):
    def get_hash(user):
        return getattr(user, "security_answer_hash", None)

    user = verify_security_question_challenge(
        db=db,
        username=payload.username,
        answer=payload.answer,
        get_user_by_username=get_user_by_username,
        get_stored_answer_hash=get_hash,
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid answer")

    return {"ok": True}
```

---

## Reference

The sections below document the lower-level building blocks (tokens, http parsing, RBAC utilities, etc.).

## Installation (local project)

For now, the code lives inside your project (e.g. `iam_utils` folder). To use it from application code, make sure the project root is on `PYTHONPATH`, or install it in editable mode:

```bash
pip install -e .
```

(with a suitable `pyproject.toml` or `setup.py` once you package it).

---

## Configuration

`iam_utils.config` exposes a simple configuration object used by the security utilities:

```python
from iam_utils.config import iam_config

# Override defaults at application startup
iam_config.SECRET_KEY = "super-secret-from-env"
iam_config.ACCESS_TOKEN_EXPIRE_MINUTES = 60
# ALGORITHM defaults to "HS256" but can be changed if needed
```

You can also load overrides from environment variables (useful in production):

```python
iam_config.load_from_env()  # looks for IAM_* variables

# Supported variables (with default prefix IAM_):
#   IAM_SECRET_KEY
#   IAM_ALGORITHM
#   IAM_ACCESS_TOKEN_EXPIRE_MINUTES
#   IAM_PASSWORD_SCHEMES   # e.g. "bcrypt,argon2"
#   IAM_PASSWORD_DEPRECATED
```

If you prefer, you can also access the resolved values directly:

```python
import iam_utils

print(iam_utils.SECRET_KEY, iam_utils.ALGORITHM, iam_utils.ACCESS_TOKEN_EXPIRE_MINUTES)
```

Note: configuration values can be read directly from `iam_config`.
For dynamic reads after calling `iam_config.load_from_env()`, prefer `iam_config.SECRET_KEY`.

---

## Password hashing & verification

```python
from iam_utils.security import get_password_hash, verify_password

hashed = get_password_hash("plain-password")

assert verify_password("plain-password", hashed) is True
assert verify_password("wrong", hashed) is False
```

You can store `hashed` on your user model (e.g. `user.hashed_password`).

---

## JWT access tokens

Token creation and verification is implemented in `iam_utils.tokens`.
You can still import the public helpers from the package root (`iam_utils`).

### Create a token for a subject

```python
from datetime import timedelta
from iam_utils.tokens import create_subject_token

# subject can be user id, email, thread id, etc.
access_token = create_subject_token(
    subject="user@example.com",
    expires_delta=timedelta(minutes=30),
    additional_claims={"permissions": "user"},
)
```

In many cases you won't need it, but there is also a lower-level helper that
encodes arbitrary JWT payloads using the configured `SECRET_KEY` and
`ALGORITHM`:

```python
from datetime import timedelta
from iam_utils.tokens import create_access_token, decode_access_token

payload = {"sub": "user@example.com", "role": "user"}

token = create_access_token(data=payload, expires_delta=timedelta(minutes=30))
decoded = decode_access_token(token)
assert decoded["sub"] == "user@example.com"
```

### Verify a token

```python
from iam_utils.tokens import CredentialsError, verify_token

try:
    subject = verify_token(access_token)
except CredentialsError:
    # invalid / expired token
    ...
else:
    # subject is the "sub" claim (e.g. user email or id)
    ...
```

`verify_token` will raise `TokenFormatError` if the token string is malformed (not in JWT format).

---

### Token revocation (denylist) and one-time tokens

If you maintain a **denylist** of revoked JTIs (e.g. in Redis/DB), you can enforce revocation checks:

```python
from iam_utils.tokens import (
    CredentialsError,
    verify_token,
    verify_token_not_revoked,
    get_token_jti,
    get_token_exp,
)

revoked_jtis = set()


def is_jti_revoked(jti: str) -> bool:
    return jti in revoked_jtis


try:
    subject = verify_token(access_token)
    verify_token_not_revoked(access_token, is_jti_revoked=is_jti_revoked)
except CredentialsError:
    ...
else:
    jti = get_token_jti(access_token)
    exp = get_token_exp(access_token)
    ...
```

You can also consume a token as **one-time use** by tracking its JTI:

```python
from iam_utils.tokens import CredentialsError, consume_one_time_token

used_jtis = set()


def is_jti_used(jti: str) -> bool:
    return jti in used_jtis


def mark_jti_used(jti: str, expires_at):
    used_jtis.add(jti)


try:
    subject = consume_one_time_token(
        token=access_token,
        is_jti_used=is_jti_used,
        mark_jti_used=mark_jti_used,
    )
except CredentialsError:
    # invalid / expired OR already consumed
    ...
else:
    # valid, and now marked as used
    ...
```

## CSRF tokens

CSRF tokens are just JWTs with an extra `{"csrf": True}` claim.

```python
from datetime import timedelta
from iam_utils.tokens import CredentialsError, create_csrf_token, verify_csrf_token

csrf_token = create_csrf_token(
    subject="user@example.com",
    expires_delta=timedelta(minutes=10),
)

try:
    subject = verify_csrf_token(csrf_token)
except CredentialsError:
    # invalid / expired / not marked as CSRF
    ...
else:
    # valid CSRF token for this subject
    ...
```

You can, for example, send this CSRF token in a cookie and require it again in a header or form field.

---

## Refresh tokens

Refresh tokens are JWTs with an extra `{"refresh": True}` claim.

```python
from datetime import timedelta
from iam_utils.tokens import (
    CredentialsError,
    create_refresh_token,
    verify_refresh_token,
    create_token_pair,
    rotate_refresh_token,
)

refresh_token = create_refresh_token(
    subject="user@example.com",
    expires_delta=timedelta(days=7),  # typically longer-lived than access tokens
)

try:
    subject = verify_refresh_token(refresh_token)
except CredentialsError:
    # invalid / expired / not marked as refresh
    ...
else:
    # valid refresh token for this subject
    ...
```

You can also create and rotate token pairs (access + refresh) in one call:

```python
pair = create_token_pair(
    subject="user@example.com",
    access_expires=timedelta(minutes=30),
    refresh_expires=timedelta(days=7),
)

new_pair = rotate_refresh_token(
    pair["refresh_token"],
    access_expires=timedelta(minutes=30),
    refresh_expires=timedelta(days=7),
)
```

---

## Generic authentication helpers

These functions are **stack- and ORM-agnostic**. You pass in your own DB/session and callbacks.

### Authenticate a user by username (default) or email

```python
from iam_utils.auth import authenticate_user
from iam_utils.security import verify_password

# your own functions, using your ORM
from my_app.db import get_user_by_username, get_user_by_email

user = authenticate_user(
    db=db_session,
    username="user",
    password="plain-password",
    get_user_by_username=get_user_by_username,
    verify_password_fn=verify_password,
)

if user is None:
    # invalid credentials
    ...
else:
    # authenticated user object
    ...
```

### Check if an email can sign up

```python
from iam_utils.auth import can_sign_up_user
from my_app.db import get_user_by_email

if can_sign_up_user(db=db_session, email="user@example.com", get_user_by_email=get_user_by_email):
    # safe to create a new user
    ...
else:
    # email already taken
    ...
```

### Ensure user is active / superuser

```python
from iam_utils.auth import (
    ensure_user_is_active,
    ensure_user_is_superuser,
    ensure_user_has_permissions,
    ensure_user_has_any_permission,
    user_has_permissions,
    InactiveUserError,
    PermissionDeniedError,
)

try:
    ensure_user_is_active(user)
    ensure_user_is_superuser(user)
    ensure_user_has_permissions(user, ["read", "write"])
    ensure_user_has_any_permission(user, ["admin", "moderator"])
except InactiveUserError:
    # handle inactive user
    ...
except PermissionDeniedError:
    # handle non-superuser
    ...

has_basic_perms = user_has_permissions(user, ["read", "write"])
has_any_admin = user_has_permissions(user, ["admin", "moderator"], any_=True)
```

---

## Sanitization utilities

```python
from iam_utils.sanitization import (
    sanitize_string,
    sanitize_email,
    sanitize_dict,
    sanitize_list,
    strip_html_tags,
    normalize_whitespace,
    sanitize_url,
    validate_password_strength,
)

safe_name = sanitize_string(user_input)
safe_email = sanitize_email("User@Example.COM")  # lowercased, basic format check

validate_password_strength("StrongP@ssw0rd!")  # raises ValueError if too weak

payload = {"name": "<script>alert(1)</script>", "tags": ["<b>tag</b>"]}
clean_payload = sanitize_dict(payload)

plain = strip_html_tags("<b>Hello</b> world")   # "Hello world"
normalized = normalize_whitespace("Hello\n   world")  # "Hello world"

safe_url = sanitize_url("https://example.com/path")
```

---

## General-purpose security helpers

`iam_utils.security` also provides some low-level utilities:

```python
from iam_utils.security import (
    generate_random_token,
    constant_time_compare,
)

token = generate_random_token()          # URL-safe random string
short_token = generate_random_token(16)  # 16 bytes of entropy

# Constant-time comparison (e.g. for tokens, nonces, etc.)
if constant_time_compare(user_input_token, expected_token):
    ...

...
```

These are intentionally small building blocks you can plug into your own
security flows.

---

## Errors / Exceptions

The library defines several auth-related exceptions you can use for clearer error handling:

```python
from iam_utils.tokens import AuthError, TokenError, CredentialsError, TokenFormatError, InvalidSubjectError
from iam_utils.auth import InactiveUserError, PermissionDeniedError
```

All are regular Python exceptions and can be caught and translated into framework-specific responses (e.g. FastAPI `HTTPException`, Django `PermissionDenied`, etc.).

---

## Stack-independent CSRF middleware logic

`iam_utils.middleware` provides helpers you can plug into any framework's middleware layer.

For **cookie-based authentication**, a common approach is the **double-submit CSRF** pattern:

- Set a `csrftoken` cookie (typically **not** `HttpOnly`) so your frontend can read it.
- For state-changing requests (POST/PUT/PATCH/DELETE), your frontend copies that value into an `X-CSRF-Token` header.
- On the backend, require that cookie + header match, and verify the token is a valid CSRF token.

You can generate CSRF tokens with `iam_utils.tokens.create_csrf_token(subject=...)` (often tied to the current user).

```python
from iam_utils.middleware import validate_csrf_request, CSRFError


def my_csrf_middleware(handler):
    def wrapper(request):
        try:
            subject = validate_csrf_request(
                method=request.method,
                header_token=request.headers.get("X-CSRF-Token"),
                cookie_token=request.cookies.get("csrftoken"),
            )
        except CSRFError as exc:
            # Translate to your framework's error/response
            return make_forbidden_response(str(exc))

        # Optionally store subject on the request context
        request.csrf_subject = subject
        return handler(request)

    return wrapper
```

The same `validate_csrf_request` function can be used in FastAPI, Django, Starlette,
or any other stack that exposes the HTTP method, headers, and cookies.

You can also use generic helpers for security headers and origin validation:

```python
from iam_utils.middleware import apply_security_headers, validate_origin, OriginError


def my_security_middleware(handler):
    def wrapper(request):
        # Validate Origin header if needed
        try:
            validate_origin(request.headers.get("Origin"), ["https://example.com"])
        except OriginError as exc:
            return make_forbidden_response(str(exc))

        response = handler(request)

        # Apply common security headers before returning
        response.headers.update(
            apply_security_headers(
                response.headers,
                content_security_policy="default-src 'self'",
                hsts_max_age=31536000,
            )
        )
        return response

    return wrapper
```
