from importlib import import_module

from .config import IAMConfig, iam_config

__all__ = [
    "IAMConfig",
    "iam_config",
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "create_access_token",
    "decode_access_token",
    "get_password_hash",
    "verify_password",
    "generate_random_token",
    "constant_time_compare",
    "extract_bearer_token",
    "require_bearer_token",
    "BearerTokenError",
    "get_token_from_headers",
    "get_token_from_cookies",
    "get_token_jti",
    "get_token_exp",
    "verify_token_not_revoked",
    "consume_one_time_token",
    "normalize_security_answer",
    "hash_security_answer",
    "verify_security_answer",
    "expand_permissions",
    "user_effective_permissions",
    "user_has_effective_permissions",
    "sanitize_dict",
    "sanitize_email",
    "sanitize_list",
    "sanitize_string",
    "strip_html_tags",
    "normalize_whitespace",
    "sanitize_url",
    "validate_password_strength",
    "create_subject_token",
    "verify_token",
    "create_csrf_token",
    "verify_csrf_token",
    "create_refresh_token",
    "verify_refresh_token",
    "create_token_pair",
    "rotate_refresh_token",
    "authenticate_user",
    "can_sign_up_user",
    "login_user",
    "UserSchema",
    "refresh_session",
    "logout_session",
    "validate_user",
    "ensure_user_has_effective_permissions",
    "get_user_roles",
    "get_user_from_access_token",
    "require_user_from_access_token",
    "build_auth_cookie_specs",
    "apply_auth_cookie_specs",
    "build_auth_cookie_delete_specs",
    "apply_auth_cookie_delete_specs",
    "verify_security_question_challenge",
    "ensure_user_is_active",
    "ensure_user_is_superuser",
    "ensure_user_has_permissions",
    "ensure_user_has_any_permission",
    "user_has_permissions",
    "AuthError",
    "TokenError",
    "CredentialsError",
    "TokenFormatError",
    "InvalidSubjectError",
    "InactiveUserError",
    "PermissionDeniedError",
    "CSRFError",
    "OriginError",
    "apply_security_headers",
    "validate_csrf_request",
    "validate_origin",
    "auth",
    "config",
    "http",
    "middleware",
    "rbac",
    "sanitization",
    "security",
    "security_questions",
    "tokens",
]


def __getattr__(name: str):
    if name in {"SECRET_KEY", "ALGORITHM", "ACCESS_TOKEN_EXPIRE_MINUTES"}:
        return getattr(iam_config, name)

    if name in {
        "auth",
        "config",
        "http",
        "middleware",
        "rbac",
        "sanitization",
        "security",
        "security_questions",
        "tokens",
    }:
        return import_module(f"{__name__}.{name}")

    # Resolve top-level exports lazily by searching known submodules.
    # Lighter modules first so `from iam_utils import sanitize_dict` doesn't
    # pull in token/security dependencies.
    first_import_error: ImportError | None = None
    for module_name in (
        "sanitization",
        "http",
        "rbac",
        "security_questions",
        "auth",
        "middleware",
        "tokens",
        "security",
    ):
        try:
            module = import_module(f"{__name__}.{module_name}")
        except ImportError as exc:
            if first_import_error is None:
                first_import_error = exc
            continue
        try:
            return getattr(module, name)
        except AttributeError:
            continue

    if name in __all__ and first_import_error is not None:
        raise first_import_error

    raise AttributeError(name)


def __dir__():
    return sorted(set(globals().keys()) | set(__all__))
