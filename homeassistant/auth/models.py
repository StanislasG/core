"""Auth models."""
from __future__ import annotations

from datetime import datetime, timedelta
import secrets
from typing import NamedTuple
import uuid

import attr

from homeassistant.const import __version__
from homeassistant.util import dt as dt_util

from . import permissions as perm_mdl
from .const import GROUP_ID_ADMIN
from .permissions.types import PolicyType

TOKEN_TYPE_NORMAL = "normal"
TOKEN_TYPE_SYSTEM = "system"
TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN = "long_lived_access_token"


@attr.s(slots=True)
class Group:
    """A group."""

    name: str | None = attr.ib()
    policy: perm_mdl.PolicyType = attr.ib()
    id: str = attr.ib(factory=lambda: uuid.uuid4().hex)
    system_generated: bool = attr.ib(default=False)
    group_ids: list[str] = attr.ib(factory=list, eq=False, order=False)
    group_ids_obj: list[Group] = attr.ib(factory=list, eq=False, order=False)


@attr.s(slots=True)
class User:
    """A user."""

    name: str | None = attr.ib()
    perm_lookup: perm_mdl.PermissionLookup = attr.ib(eq=False, order=False)
    id: str = attr.ib(factory=lambda: uuid.uuid4().hex)
    is_owner: bool = attr.ib(default=False)
    is_active: bool = attr.ib(default=False)
    system_generated: bool = attr.ib(default=False)
    local_only: bool = attr.ib(default=False)

    groups: list[Group] = attr.ib(factory=list, eq=False, order=False)

    # List of credentials of a user.
    credentials: list[Credentials] = attr.ib(factory=list, eq=False, order=False)

    # Tokens associated with a user.
    refresh_tokens: dict[str, RefreshToken] = attr.ib(
        factory=dict, eq=False, order=False
    )

    _permissions: perm_mdl.PolicyPermissions | None = attr.ib(
        init=False,
        eq=False,
        order=False,
        default=None,
    )

    decisions: list[Decision] = attr.ib(factory=list, eq=False, order=False)

    @property
    def permissions(self) -> perm_mdl.AbstractPermissions:
        """Return permissions object for user."""
        if self.is_owner:
            return perm_mdl.OwnerPermissions

        if self._permissions is not None:
            return self._permissions

        self._permissions = perm_mdl.PolicyPermissions(
            perm_mdl.merge_policies(
                [self.find_policy_from_group(group) for group in self.groups]
            ),
            self.perm_lookup,
        )

        return self._permissions

    def find_policy_from_group(self, group: Group) -> PolicyType:
        """Return recursive Policies."""
        curr: PolicyType = group.policy

        hiertitage: list[PolicyType] = []
        if len(group.group_ids) > 0:
            for group_id_obj in group.group_ids_obj:
                new: PolicyType = self.find_policy_from_group(group_id_obj)
                hiertitage.append({"entities": new["entities"]})
        total: list[PolicyType] = hiertitage + (
            [{"entities": curr["entities"]}]
            if curr is not None and "entities" in curr
            else []
        )
        if len(total) > 0:
            return perm_mdl.merge_policies(total)
        return {"None": None}

    @property
    def is_admin(self) -> bool:
        """Return if user is part of the admin group."""
        if self.is_owner:
            return True

        return self.is_active and any(gr.id == GROUP_ID_ADMIN for gr in self.groups)

    def invalidate_permission_cache(self) -> None:
        """Invalidate permission cache."""
        self._permissions = None


@attr.s(slots=True)
class RefreshToken:
    """RefreshToken for a user to grant new access tokens."""

    user: User = attr.ib()
    client_id: str | None = attr.ib()
    access_token_expiration: timedelta = attr.ib()
    client_name: str | None = attr.ib(default=None)
    client_icon: str | None = attr.ib(default=None)
    token_type: str = attr.ib(
        default=TOKEN_TYPE_NORMAL,
        validator=attr.validators.in_(
            (TOKEN_TYPE_NORMAL, TOKEN_TYPE_SYSTEM, TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN)
        ),
    )
    id: str = attr.ib(factory=lambda: uuid.uuid4().hex)
    created_at: datetime = attr.ib(factory=dt_util.utcnow)
    token: str = attr.ib(factory=lambda: secrets.token_hex(64))
    jwt_key: str = attr.ib(factory=lambda: secrets.token_hex(64))

    last_used_at: datetime | None = attr.ib(default=None)
    last_used_ip: str | None = attr.ib(default=None)

    credential: Credentials | None = attr.ib(default=None)

    version: str | None = attr.ib(default=__version__)


@attr.s(slots=True)
class Credentials:
    """Credentials for a user on an auth provider."""

    auth_provider_type: str = attr.ib()
    auth_provider_id: str | None = attr.ib()

    # Allow the auth provider to store data to represent their auth.
    data: dict = attr.ib()

    id: str = attr.ib(factory=lambda: uuid.uuid4().hex)
    is_new: bool = attr.ib(default=True)


class UserMeta(NamedTuple):
    """User metadata."""

    name: str | None
    is_active: bool


@attr.s(slots=True)
class Decision:
    """Decision."""

    source: str = attr.ib()  # id user/group
    target: str = attr.ib()  # id user/group
    group: str = attr.ib()
    action: str = attr.ib()
    reject: list[str] = attr.ib(factory=list, eq=False, order=False)
    approve: list[str] = attr.ib(factory=list, eq=False, order=False)
    result: bool = attr.ib(default=None)
    policy: PolicyType | None = attr.ib(default=None)
