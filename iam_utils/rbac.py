from typing import Any, Dict, Iterable, Optional, Set


def _normalize_set(value: Any, *, separator: str = ",") -> Optional[Set[str]]:
    if value is None:
        return None

    if isinstance(value, str):
        return {p.strip() for p in value.split(separator) if p.strip()}

    try:
        return {str(p).strip() for p in value}
    except TypeError:
        return {str(value).strip()}


def expand_permissions(
    roles: Iterable[str],
    *,
    role_to_permissions: Dict[str, Iterable[str]],
) -> Set[str]:
    """Expand a list of roles to a set of permissions using a mapping."""

    out: Set[str] = set()
    for role in roles:
        role_key = str(role).strip()
        if not role_key:
            continue
        perms = role_to_permissions.get(role_key, [])
        for p in perms:
            p2 = str(p).strip()
            if p2:
                out.add(p2)
    return out


def user_effective_permissions(
    user: Any,
    *,
    role_to_permissions: Dict[str, Iterable[str]],
    permissions_attr: str = "permissions",
    roles_attr: str = "roles",
    separator: str = ",",
) -> Set[str]:
    """Return the union of direct user permissions and role-derived permissions."""

    direct = _normalize_set(getattr(user, permissions_attr, None), separator=separator) or set()
    roles = _normalize_set(getattr(user, roles_attr, None), separator=separator) or set()

    expanded = expand_permissions(roles, role_to_permissions=role_to_permissions)
    return set(direct) | set(expanded)


def user_has_effective_permissions(
    user: Any,
    required: Iterable[str],
    *,
    role_to_permissions: Dict[str, Iterable[str]],
    any_: bool = False,
    permissions_attr: str = "permissions",
    roles_attr: str = "roles",
    separator: str = ",",
) -> bool:
    """Check permissions against effective permissions (direct + via roles)."""

    perms = user_effective_permissions(
        user,
        role_to_permissions=role_to_permissions,
        permissions_attr=permissions_attr,
        roles_attr=roles_attr,
        separator=separator,
    )

    normalized_required = [str(p).strip() for p in required]
    if any_:
        return any(p in perms for p in normalized_required)
    return all(p in perms for p in normalized_required)
