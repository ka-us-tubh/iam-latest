"""This file contains the authentication utilities for the application."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from .tokens import AuthError, TokenError
from .tokens import (
    CredentialsError,
    InvalidSubjectError,
    create_token_pair,
    get_token_exp,
    get_token_jti,
    verify_token_not_revoked,
    verify_refresh_token,
)
from .rbac import user_has_effective_permissions
from .security_questions import verify_security_answer


__all__ = [
    "AuthError",
    "InactiveUserError",
    "PermissionDeniedError",
    "UserSchema",
    "validate_user",
    "ensure_user_has_effective_permissions",
    "get_user_roles",
    "get_user_from_access_token",
    "require_user_from_access_token",
    "authenticate_user",
    "can_sign_up_user",
    "ensure_user_is_active",
    "ensure_user_is_superuser",
    "ensure_user_has_permissions",
    "ensure_user_has_any_permission",
    "user_has_permissions",
    "login_user",
    "refresh_session",
    "logout_session",
    "build_auth_cookie_specs",
    "apply_auth_cookie_specs",
    "build_auth_cookie_delete_specs",
    "apply_auth_cookie_delete_specs",
    "verify_security_question_challenge",
]


class InactiveUserError(AuthError, ValueError):
    """Raised when an operation requires an active user but the user is inactive."""


class PermissionDeniedError(AuthError, ValueError):
    """Raised when a user does not have sufficient privileges."""


@dataclass(frozen=True)
class UserSchema:
    hashed_password_attr: str = "hashed_password"
    is_active_attr: str = "is_active"
    is_superuser_attr: str = "is_superuser"
    permissions_attr: str = "permissions"
    roles_attr: str = "roles"

    username_attr: str = "username"
    email_attr: str = "email"
    id_attr: str = "id"

    subject_getter: Optional[Callable[[Any], Any]] = None


def _schema_attr(*, value: str, default: str, schema: Optional[UserSchema], schema_value: str) -> str:
    if schema is None:
        return value
    if value != default:
        return value
    return schema_value


def login_user(
    *,
    db: Any,
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: str,
    get_user_by_username: Optional[Callable[[Any, str], Any]] = None,
    get_user_by_email: Optional[Callable[[Any, str], Any]] = None,
    verify_password_fn: Callable[[str, str], bool],
    hashed_password_attr: str = "hashed_password",
    subject_getter: Optional[Callable[[Any], Any]] = None,
    ensure_active: bool = True,
    is_active_attr: str = "is_active",
    user_schema: Optional[UserSchema] = None,
    access_expires: Optional[timedelta] = None,
    refresh_expires: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    hashed_password_attr = _schema_attr(
        value=hashed_password_attr,
        default="hashed_password",
        schema=user_schema,
        schema_value=user_schema.hashed_password_attr if user_schema is not None else "hashed_password",
    )
    is_active_attr = _schema_attr(
        value=is_active_attr,
        default="is_active",
        schema=user_schema,
        schema_value=user_schema.is_active_attr if user_schema is not None else "is_active",
    )
    if subject_getter is None and user_schema is not None:
        subject_getter = user_schema.subject_getter

    user = authenticate_user(
        db=db,
        username=username,
        email=email,
        password=password,
        get_user_by_username=get_user_by_username,
        get_user_by_email=get_user_by_email,
        verify_password_fn=verify_password_fn,
        hashed_password_attr=hashed_password_attr,
    )
    if user is None:
        return None

    if ensure_active:
        ensure_user_is_active(user, attr=is_active_attr)

    if subject_getter is None:
        username_attr = _schema_attr(
            value="username",
            default="username",
            schema=user_schema,
            schema_value=user_schema.username_attr if user_schema is not None else "username",
        )
        email_attr = _schema_attr(
            value="email",
            default="email",
            schema=user_schema,
            schema_value=user_schema.email_attr if user_schema is not None else "email",
        )
        id_attr = _schema_attr(
            value="id",
            default="id",
            schema=user_schema,
            schema_value=user_schema.id_attr if user_schema is not None else "id",
        )

        if username is not None and str(username).strip():
            subject = getattr(user, username_attr, None)
            if subject is None:
                subject = username
        elif email is not None and str(email).strip():
            subject = getattr(user, email_attr, None)
            if subject is None:
                subject = email
        else:
            subject = getattr(user, username_attr, None)
            if subject is None:
                subject = getattr(user, email_attr, None)

        if subject is None:
            subject = getattr(user, id_attr, None)
    else:
        subject = subject_getter(user)

    if subject is None or (isinstance(subject, str) and not subject.strip()):
        raise InvalidSubjectError("subject must be a non-empty string")

    return create_token_pair(
        subject=str(subject),
        access_expires=access_expires,
        refresh_expires=refresh_expires,
        additional_claims=additional_claims,
    )


def refresh_session(
    refresh_token: str,
    *,
    is_jti_revoked: Optional[Callable[[str], bool]] = None,
    revoke_jti: Optional[Callable[[str, Any], None]] = None,
    access_expires: Optional[timedelta] = None,
    refresh_expires: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, str]]:
    try:
        subject = verify_refresh_token(refresh_token)
    except TokenError:
        return None

    jti = get_token_jti(refresh_token)
    if jti and is_jti_revoked is not None:
        try:
            if is_jti_revoked(jti):
                return None
        except Exception:
            return None

    if jti and revoke_jti is not None:
        try:
            revoke_jti(jti, get_token_exp(refresh_token))
        except Exception:
            return None

    return create_token_pair(
        subject=subject,
        access_expires=access_expires,
        refresh_expires=refresh_expires,
        additional_claims=additional_claims,
    )


def logout_session(
    *,
    revoke_jti: Callable[[str, Any], None],
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
) -> int:
    revoked = 0
    for token in (access_token, refresh_token):
        if not token:
            continue
        jti = get_token_jti(token)
        if not jti:
            continue
        try:
            revoke_jti(jti, get_token_exp(token))
        except Exception:
            continue
        revoked += 1
    return revoked


def authenticate_user(
    *,
    db: Any,
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: str,
    get_user_by_username: Optional[Callable[[Any, str], Any]] = None,
    get_user_by_email: Optional[Callable[[Any, str], Any]] = None,
    verify_password_fn: Callable[[str, str], bool],
    hashed_password_attr: str = "hashed_password",
    user_schema: Optional[UserSchema] = None,
) -> Optional[Any]:
    """Generic helper to authenticate a user by username/email and password.

    Username is the default identifier. To authenticate by email, pass ``email``
    and a ``get_user_by_email`` callback.

    Returns the user object on success, or None on failure.
    """

    hashed_password_attr = _schema_attr(
        value=hashed_password_attr,
        default="hashed_password",
        schema=user_schema,
        schema_value=user_schema.hashed_password_attr if user_schema is not None else "hashed_password",
    )

    user = _get_user_by_identifier(
        db=db,
        username=username,
        email=email,
        get_user_by_username=get_user_by_username,
        get_user_by_email=get_user_by_email,
    )
    if not user:
        return None
    if not verify_password_fn(password, str(getattr(user, hashed_password_attr, ""))):
        return None
    return user


def can_sign_up_user(
    *,
    db: Any,
    email: str,
    get_user_by_email: Callable[[Any, str], Any],
) -> bool:
    """Return True if an email is available for sign-up, False if already taken."""

    existing = get_user_by_email(db, email)
    return existing is None


def validate_user(
    user: Any,
    *,
    ensure_active: bool = True,
    is_active_attr: str = "is_active",
    require_superuser: bool = False,
    is_superuser_attr: str = "is_superuser",
    required_permissions: Optional[Iterable[str]] = None,
    any_permission: bool = False,
    permissions_attr: str = "permissions",
    permissions_separator: str = ",",
    user_schema: Optional[UserSchema] = None,
) -> Any:
    is_active_attr = _schema_attr(
        value=is_active_attr,
        default="is_active",
        schema=user_schema,
        schema_value=user_schema.is_active_attr if user_schema is not None else "is_active",
    )
    is_superuser_attr = _schema_attr(
        value=is_superuser_attr,
        default="is_superuser",
        schema=user_schema,
        schema_value=user_schema.is_superuser_attr if user_schema is not None else "is_superuser",
    )
    permissions_attr = _schema_attr(
        value=permissions_attr,
        default="permissions",
        schema=user_schema,
        schema_value=user_schema.permissions_attr if user_schema is not None else "permissions",
    )

    if ensure_active:
        ensure_user_is_active(user, attr=is_active_attr)
    if require_superuser:
        ensure_user_is_superuser(user, attr=is_superuser_attr)
    if required_permissions:
        if any_permission:
            ensure_user_has_any_permission(
                user,
                required_permissions,
                attr=permissions_attr,
                separator=permissions_separator,
            )
        else:
            ensure_user_has_permissions(
                user,
                required_permissions,
                attr=permissions_attr,
                separator=permissions_separator,
            )
    return user


def ensure_user_has_effective_permissions(
    user: Any,
    required: Iterable[str],
    *,
    role_to_permissions: Dict[str, Iterable[str]],
    any_: bool = False,
    permissions_attr: str = "permissions",
    roles_attr: str = "roles",
    separator: str = ",",
) -> Any:
    if not user_has_effective_permissions(
        user,
        required,
        role_to_permissions=role_to_permissions,
        any_=any_,
        permissions_attr=permissions_attr,
        roles_attr=roles_attr,
        separator=separator,
    ):
        raise PermissionDeniedError("Missing required permissions")
    return user


def get_user_from_access_token(
    access_token: str,
    *,
    db: Any,
    get_user_by_subject: Callable[[Any, str], Any],
    is_jti_revoked: Optional[Callable[[str], bool]] = None,
    ensure_active: bool = True,
    is_active_attr: str = "is_active",
    require_superuser: bool = False,
    is_superuser_attr: str = "is_superuser",
    required_permissions: Optional[Iterable[str]] = None,
    any_permission: bool = False,
    role_to_permissions: Optional[Dict[str, Iterable[str]]] = None,
    permissions_attr: str = "permissions",
    roles_attr: str = "roles",
    separator: str = ",",
    user_schema: Optional[UserSchema] = None,
) -> Optional[Any]:
    is_active_attr = _schema_attr(
        value=is_active_attr,
        default="is_active",
        schema=user_schema,
        schema_value=user_schema.is_active_attr if user_schema is not None else "is_active",
    )
    is_superuser_attr = _schema_attr(
        value=is_superuser_attr,
        default="is_superuser",
        schema=user_schema,
        schema_value=user_schema.is_superuser_attr if user_schema is not None else "is_superuser",
    )
    permissions_attr = _schema_attr(
        value=permissions_attr,
        default="permissions",
        schema=user_schema,
        schema_value=user_schema.permissions_attr if user_schema is not None else "permissions",
    )
    roles_attr = _schema_attr(
        value=roles_attr,
        default="roles",
        schema=user_schema,
        schema_value=user_schema.roles_attr if user_schema is not None else "roles",
    )

    subject = verify_token_not_revoked(access_token, is_jti_revoked=is_jti_revoked)
    if subject is None:
        return None

    user = get_user_by_subject(db, subject)
    if user is None:
        return None

    if role_to_permissions is None:
        validate_user(
            user,
            ensure_active=ensure_active,
            is_active_attr=is_active_attr,
            require_superuser=require_superuser,
            is_superuser_attr=is_superuser_attr,
            required_permissions=required_permissions,
            any_permission=any_permission,
            permissions_attr=permissions_attr,
            permissions_separator=separator,
            user_schema=user_schema,
        )
    else:
        validate_user(
            user,
            ensure_active=ensure_active,
            is_active_attr=is_active_attr,
            require_superuser=require_superuser,
            is_superuser_attr=is_superuser_attr,
            required_permissions=None,
            user_schema=user_schema,
        )
        if required_permissions:
            ensure_user_has_effective_permissions(
                user,
                required_permissions,
                role_to_permissions=role_to_permissions,
                any_=any_permission,
                permissions_attr=permissions_attr,
                roles_attr=roles_attr,
                separator=separator,
            )

    return user


def require_user_from_access_token(
    access_token: str,
    *,
    db: Any,
    get_user_by_subject: Callable[[Any, str], Any],
    is_jti_revoked: Optional[Callable[[str], bool]] = None,
    ensure_active: bool = True,
    is_active_attr: str = "is_active",
    require_superuser: bool = False,
    is_superuser_attr: str = "is_superuser",
    required_permissions: Optional[Iterable[str]] = None,
    any_permission: bool = False,
    role_to_permissions: Optional[Dict[str, Iterable[str]]] = None,
    permissions_attr: str = "permissions",
    roles_attr: str = "roles",
    separator: str = ",",
    user_schema: Optional[UserSchema] = None,
) -> Any:
    user = get_user_from_access_token(
        access_token,
        db=db,
        get_user_by_subject=get_user_by_subject,
        is_jti_revoked=is_jti_revoked,
        ensure_active=ensure_active,
        is_active_attr=is_active_attr,
        require_superuser=require_superuser,
        is_superuser_attr=is_superuser_attr,
        required_permissions=required_permissions,
        any_permission=any_permission,
        role_to_permissions=role_to_permissions,
        permissions_attr=permissions_attr,
        roles_attr=roles_attr,
        separator=separator,
        user_schema=user_schema,
    )
    if user is None:
        raise CredentialsError("Invalid credentials")
    return user


def get_user_roles(user: Any, *, attr: str = "roles", separator: str = ",") -> List[str]:
    roles_obj = getattr(user, attr, None)
    if roles_obj is None:
        return []
    if isinstance(roles_obj, str):
        return [r.strip() for r in roles_obj.split(separator) if r.strip()]
    try:
        return [str(r).strip() for r in roles_obj if str(r).strip()]
    except TypeError:
        return [str(roles_obj).strip()] if str(roles_obj).strip() else []


def build_auth_cookie_specs(
    tokens: Dict[str, str],
    *,
    access_cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
    httponly: bool = True,
    secure: bool = True,
    samesite: str = "lax",
    path: str = "/",
    access_path: Optional[str] = None,
    refresh_path: Optional[str] = None,
    domain: Optional[str] = None,
    set_max_age_from_exp: bool = False,
) -> Dict[str, Dict[str, Any]]:
    access_path_resolved = path if access_path is None else access_path
    refresh_path_resolved = path if refresh_path is None else refresh_path

    specs: Dict[str, Dict[str, Any]] = {}
    if "access_token" in tokens:
        access_max_age: Optional[int] = None
        if set_max_age_from_exp:
            exp = get_token_exp(tokens["access_token"])
            if exp is not None:
                seconds = int((exp - datetime.now(timezone.utc)).total_seconds())
                if seconds > 0:
                    access_max_age = seconds

        specs[access_cookie_name] = {
            "value": tokens["access_token"],
            "httponly": httponly,
            "secure": secure,
            "samesite": samesite,
            "path": access_path_resolved,
        }
        if domain is not None:
            specs[access_cookie_name]["domain"] = domain
        if access_max_age is not None:
            specs[access_cookie_name]["max_age"] = access_max_age

    if "refresh_token" in tokens:
        refresh_max_age: Optional[int] = None
        if set_max_age_from_exp:
            exp = get_token_exp(tokens["refresh_token"])
            if exp is not None:
                seconds = int((exp - datetime.now(timezone.utc)).total_seconds())
                if seconds > 0:
                    refresh_max_age = seconds

        specs[refresh_cookie_name] = {
            "value": tokens["refresh_token"],
            "httponly": httponly,
            "secure": secure,
            "samesite": samesite,
            "path": refresh_path_resolved,
        }
        if domain is not None:
            specs[refresh_cookie_name]["domain"] = domain
        if refresh_max_age is not None:
            specs[refresh_cookie_name]["max_age"] = refresh_max_age

    return specs


def apply_auth_cookie_specs(
    set_cookie: Callable[..., Any],
    specs: Dict[str, Dict[str, Any]],
) -> None:
    for name, spec in specs.items():
        value = spec.get("value")
        options = {k: v for k, v in spec.items() if k != "value"}
        set_cookie(name, value, **options)


def build_auth_cookie_delete_specs(
    *,
    access_cookie_name: str = "access_token",
    refresh_cookie_name: str = "refresh_token",
    path: str = "/",
    access_path: Optional[str] = None,
    refresh_path: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    access_path_resolved = path if access_path is None else access_path
    refresh_path_resolved = path if refresh_path is None else refresh_path

    access_spec: Dict[str, Any] = {"path": access_path_resolved}
    refresh_spec: Dict[str, Any] = {"path": refresh_path_resolved}
    if domain is not None:
        access_spec["domain"] = domain
        refresh_spec["domain"] = domain

    return {
        access_cookie_name: access_spec,
        refresh_cookie_name: refresh_spec,
    }


def apply_auth_cookie_delete_specs(
    delete_cookie: Callable[..., Any],
    specs: Dict[str, Dict[str, Any]],
) -> None:
    for name, options in specs.items():
        delete_cookie(name, **options)


def verify_security_question_challenge(
    *,
    db: Any,
    username: Optional[str] = None,
    email: Optional[str] = None,
    answer: str,
    get_user_by_username: Optional[Callable[[Any, str], Any]] = None,
    get_user_by_email: Optional[Callable[[Any, str], Any]] = None,
    get_stored_answer_hash: Callable[[Any], Optional[str]],
    ensure_active: bool = True,
    is_active_attr: str = "is_active",
    user_schema: Optional[UserSchema] = None,
) -> Optional[Any]:
    user = _get_user_by_identifier(
        db=db,
        username=username,
        email=email,
        get_user_by_username=get_user_by_username,
        get_user_by_email=get_user_by_email,
    )
    if user is None:
        return None

    if ensure_active:
        is_active_attr = _schema_attr(
            value=is_active_attr,
            default="is_active",
            schema=user_schema,
            schema_value=user_schema.is_active_attr if user_schema is not None else "is_active",
        )
        ensure_user_is_active(user, attr=is_active_attr)

    stored_hash = get_stored_answer_hash(user)
    if not stored_hash:
        return None

    if not verify_security_answer(answer, stored_hash):
        return None

    return user


def ensure_user_is_active(user: Any, *, attr: str = "is_active") -> Any:
    """Ensure that the given user is active.

    Raises ValueError if ``user.is_active`` is falsy.
    Returns the user otherwise.
    """

    if not hasattr(user, attr):
        return user

    if not getattr(user, attr, False):
        raise InactiveUserError("Inactive user")
    return user


def ensure_user_is_superuser(user: Any, *, attr: str = "is_superuser") -> Any:
    """Ensure that the given user is a superuser.

    Raises ValueError if ``user.is_superuser`` is falsy.
    Returns the user otherwise.
    """

    if not getattr(user, attr, False):
        raise PermissionDeniedError("The user doesn't have enough privileges")
    return user


def ensure_user_has_permissions(
    user: Any,
    required: Iterable[str],
    *,
    attr: str = "permissions",
    separator: str = ",",
) -> Any:
    """Ensure that the user has all required permissions.

    ``permissions`` are read from ``getattr(user, attr, None)`` and may be
    provided as an iterable of strings or as a single string separated by
    ``separator`` (default: comma).
    """

    perms_set = _extract_permissions_set(user, attr=attr, separator=separator)
    if perms_set is None:
        raise PermissionDeniedError("User has no permissions attribute")

    missing = [p for p in (str(p).strip() for p in required) if p not in perms_set]
    if missing:
        raise PermissionDeniedError(f"Missing permissions: {', '.join(missing)}")

    return user


def user_has_permissions(
    user: Any,
    required: Iterable[str],
    *,
    any_: bool = False,
    attr: str = "permissions",
    separator: str = ",",
) -> bool:
    """Return True if the user has the required permissions.

    If ``any_`` is False (default), all permissions must be present.
    If ``any_`` is True, at least one required permission must be present.
    Missing permission attributes are treated as having no permissions.
    """

    perms_set = _extract_permissions_set(user, attr=attr, separator=separator)
    if perms_set is None:
        return False

    normalized_required = [str(p).strip() for p in required]
    if any_:
        return any(p in perms_set for p in normalized_required)
    return all(p in perms_set for p in normalized_required)


def ensure_user_has_any_permission(
    user: Any,
    required: Iterable[str],
    *,
    attr: str = "permissions",
    separator: str = ",",
) -> Any:
    """Ensure that the user has at least one of the required permissions."""

    if not user_has_permissions(user, required, any_=True, attr=attr, separator=separator):
        raise PermissionDeniedError("User lacks any of the required permissions")

    return user


def _extract_permissions_set(user: Any, *, attr: str, separator: str) -> Optional[Set[str]]:
    """Internal helper to normalize a user's permissions into a set of strings.

    Returns ``None`` if the user has no such attribute.
    """

    perms_obj = getattr(user, attr, None)
    if perms_obj is None:
        return None

    if isinstance(perms_obj, str):
        return {p.strip() for p in perms_obj.split(separator) if p.strip()}
    try:
        return {str(p).strip() for p in perms_obj}
    except TypeError:
        # Non-iterable permissions: treat as a single permission value.
        return {str(perms_obj).strip()}


def _get_user_by_identifier(
    *,
    db: Any,
    username: Optional[str],
    email: Optional[str],
    get_user_by_username: Optional[Callable[[Any, str], Any]],
    get_user_by_email: Optional[Callable[[Any, str], Any]],
) -> Optional[Any]:
    if username is not None and str(username).strip():
        if get_user_by_username is None:
            raise ValueError("get_user_by_username is required when username is provided")
        return get_user_by_username(db, str(username))

    if email is not None and str(email).strip():
        if get_user_by_email is None:
            raise ValueError("get_user_by_email is required when email is provided")
        return get_user_by_email(db, str(email))

    raise ValueError("Either username or email must be provided")
