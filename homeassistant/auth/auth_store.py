"""Storage for auth models."""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import timedelta
import hmac
from logging import getLogger
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from . import models
from .const import (
    ACCESS_TOKEN_EXPIRATION,
    GROUP_ID_ADMIN,
    GROUP_ID_READ_ONLY,
    GROUP_ID_USER,
)
from .permissions import system_policies
from .permissions.merge import merge_policies
from .permissions.models import PermissionLookup
from .permissions.types import PolicyType

STORAGE_VERSION = 1
STORAGE_KEY = "auth"
GROUP_NAME_ADMIN = "Administrators"
GROUP_NAME_USER = "Users"
GROUP_NAME_READ_ONLY = "Read Only"


class AuthStore:
    """Stores authentication info.

    Any mutation to an object should happen inside the auth store.

    The auth store is lazy. It won't load the data from disk until a method is
    called that needs it.
    """

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the auth store."""
        self.hass = hass
        self._users: dict[str, models.User] | None = None
        self._groups: dict[str, models.Group] | None = None
        self._perm_lookup: PermissionLookup | None = None
        self._store = Store[dict[str, list[dict[str, Any]]]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._lock = asyncio.Lock()

    async def async_get_groups(self) -> list[models.Group]:
        """Retrieve all users."""  # to do change
        if self._groups is None:
            await self._async_load()
            assert self._groups is not None

        return list(self._groups.values())

    async def async_get_group(self, group_id: str) -> models.Group | None:
        """Retrieve all users."""
        if self._groups is None:
            await self._async_load()
            assert self._groups is not None

        return self._groups.get(group_id)

    async def async_get_users(self) -> list[models.User]:
        """Retrieve all users."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        return list(self._users.values())

    async def async_get_user(self, user_id: str) -> models.User | None:
        """Retrieve a user by id."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        return self._users.get(user_id)

    async def async_get_user_by_name(self, user_name: str) -> models.User | None:
        """Retrieve a user by name."""
        users = await self.async_get_users()
        # if users is None:
        #     return None
        for user in users:
            if user.name == user_name:
                return user
        return None

    async def async_add_user_to_group(
        self, user: str, group: models.Group
    ) -> models.User | None:
        """Add user to group."""
        _user = await self.async_get_user_by_name(user)
        if _user is not None:
            _user.groups.append(group)
        self._async_schedule_save()
        return _user

    async def async_add_group_without_policy(self, name: str) -> models.Group | None:
        """Add a new group."""
        if self._groups is None:
            await self._async_load()
        assert self._users is not None
        assert self._groups is not None
        kwargs: dict[str, Any] = {
            "name": name,
            "policy": None,
            "system_generated": False,
            "group_ids": [],
            "group_ids_obj": [],
        }
        new_group: models.Group = models.Group(**kwargs)
        if isinstance(new_group, models.Group):
            self._groups[new_group.id] = new_group
            self._async_schedule_save_groups()
        return new_group

    async def async_add_group(
        self, name: str, entity: str, read: bool, control: bool, edit: bool
    ) -> models.Group | None:
        """Add a new group."""
        if self._groups is None:
            await self._async_load()
        assert self._users is not None
        assert self._groups is not None

        entity_dict: dict[str, bool] = {"read": read, "control": control, "edit": edit}
        new_policy: PolicyType = {"entities": {"entity_id": {entity: entity_dict}}}
        # lookup = None
        # perm = PolicyPermissions(new_policy, lookup)
        # group = models.Group(name, new_policy)

        kwargs: dict[str, Any] = {
            "name": name,
            "policy": new_policy,
        }

        new_group: models.Group = models.Group(**kwargs)
        if isinstance(new_group, models.Group):
            self._groups[new_group.id] = new_group
            self._async_schedule_save_groups()
        return new_group

        # async def async_edit_intshare(self, entity: str, intshare: int) -> None:
        #     """Edit intshare policy for specified entity."""
        #     # print("edit_int in auth", entity, intshare)
        #     self.hass.states.async_set(
        #         entity, "changedState", {"friendly_name": str(intshare)}
        #     )

        # print("after edit_int in auth", entity, intshare)
        # return None

    # async def async_get_intshare(self, entity: str) -> str | None:
    #     """Edit intshare policy for specified entity."""
    #     # print("edit_int in auth", entity, intshare)
    #     return self.hass.states.get(entity).name
    #     # print("after edit_int in auth", entity, intshare)

    async def async_create_user(
        self,
        name: str | None,
        is_owner: bool | None = None,
        is_active: bool | None = None,
        system_generated: bool | None = None,
        credentials: models.Credentials | None = None,
        group_ids: list[str] | None = None,
        local_only: bool | None = None,
    ) -> models.User:
        """Create a new user."""
        if self._users is None:
            await self._async_load()

        assert self._users is not None
        assert self._groups is not None

        groups = []
        for group_id in group_ids or []:
            if (group := self._groups.get(group_id)) is None:
                raise ValueError(f"Invalid group specified {group_id}")
            groups.append(group)

        kwargs: dict[str, Any] = {
            "name": name,
            # Until we get group management, we just put everyone in the
            # same group.
            "groups": groups,
            "perm_lookup": self._perm_lookup,
        }

        for attr_name, value in (
            ("is_owner", is_owner),
            ("is_active", is_active),
            ("local_only", local_only),
            ("system_generated", system_generated),
        ):
            if value is not None:
                kwargs[attr_name] = value

        new_user = models.User(**kwargs)

        self._users[new_user.id] = new_user

        if credentials is None:
            self._async_schedule_save()
            return new_user

        # Saving is done inside the link.
        await self.async_link_user(new_user, credentials)
        return new_user

    async def async_link_user(
        self, user: models.User, credentials: models.Credentials
    ) -> None:
        """Add credentials to an existing user."""
        user.credentials.append(credentials)
        self._async_schedule_save()
        credentials.is_new = False

    async def async_remove_user(self, user: models.User) -> None:
        """Remove a user."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        self._users.pop(user.id)
        self._async_schedule_save()

    async def async_update_user(
        self,
        user: models.User,
        name: str | None = None,
        is_active: bool | None = None,
        group_ids: list[str] | None = None,
        local_only: bool | None = None,
    ) -> None:
        """Update a user."""
        assert self._groups is not None

        if group_ids is not None:
            groups = []
            for grid in group_ids:
                if (group := self._groups.get(grid)) is None:
                    raise ValueError("Invalid group specified.")
                groups.append(group)

            user.groups = groups
            user.invalidate_permission_cache()

        for attr_name, value in (
            ("name", name),
            ("is_active", is_active),
            ("local_only", local_only),
        ):
            if value is not None:
                setattr(user, attr_name, value)

        self._async_schedule_save()

    async def async_get_users_having_permission_group(
        self, group_id: str
    ) -> list[models.User]:
        """Get users having permission (not decision power)."""
        users: list[models.User] = await self.async_get_users()
        user_with_permission: list[models.User] = []
        for user in users:
            recursif_group: list[str] = []
            # search recursively in group
            for group in user.groups:
                recursif_group.append(group.id)
                temp = await self.recursif_group(group.id)
                recursif_group.extend(temp)
            # if user.permissions.check_group(group_id):
            if group_id in recursif_group:
                user_with_permission.append(user)
        return user_with_permission

    async def recursif_group(self, group_id: str) -> list[str]:
        """Get users having permission."""
        temp = await self.async_get_group(group_id)
        if temp is None:
            return []
        group: models.Group = temp
        if (
            group.name is None
            or group.name.startswith("DM")
            or group.name.startswith("DT")
        ):
            return []
        all_group: list[str] = []
        for gro in group.group_ids:
            all_group.append(gro)
            all_group.extend(await self.recursif_group(gro))
        return all_group

    async def async_get_users_member_of_dm(self, group_id: str) -> list[models.User]:
        """Get users having decision power."""
        users: list[models.User] = await self.async_get_users()
        user_with_permission: list[models.User] = []
        for user in users:
            recursif_group: list[str] = []
            # search recursively in group
            for group in user.groups:
                recursif_group.append(group.id)
                temp = await self.recursif_group_decision(group.id)
                recursif_group.extend(temp)
            # if user.permissions.check_group(group_id):
            if group_id in recursif_group:
                user_with_permission.append(user)
        return user_with_permission

    async def recursif_group_decision(self, group_id: str) -> list[str]:
        """Get users having decision power."""
        temp = await self.async_get_group(group_id)
        if temp is None:
            return []
        group: models.Group = temp
        all_group: list[str] = []
        for gro in group.group_ids:
            all_group.append(gro)
            all_group.extend(await self.recursif_group(gro))
        return all_group

    async def async_link_entity_to_dg(self, entity_id: str, group_id: str) -> None:
        """Add entity to dg."""
        temp = await self.async_get_group(group_id)
        if temp is None:
            return None
        group: models.Group = temp

        new_policy: PolicyType = {
            "entities": {
                "entity_ids": {
                    entity_id: {
                        "read": True,
                        "control": True,
                        "edit": True,
                    }
                }
            }
        }

        policies: PolicyType = merge_policies([group.policy, new_policy])
        group.policy = policies

        if self._groups is not None:
            self._groups[group_id] = group
        self._async_schedule_save()
        return None

    async def async_add_dg(
        self,
        name: str,
    ) -> str | None:
        """Create DG and return his id."""
        temp = await self.async_add_group_without_policy("DG_" + name)
        if temp is None:
            return None
        group: models.Group = temp
        return group.id

    async def async_add_dt(self, name: str) -> str | None:
        """Create DT and return his id."""
        temp = await self.async_add_group_without_policy("DT_" + name)
        if temp is None:
            return None
        group: models.Group = temp
        return group.id

    async def async_add_dm(self, name: str) -> str | None:
        """Create DM and return his id."""
        temp = await self.async_add_group_without_policy("DM_" + name)
        if temp is None:
            return None
        group: models.Group = temp
        return group.id

    async def async_set_policy(self, group_id: str, policy: PolicyType) -> None:
        """Set policy."""
        temp = await self.async_get_group(group_id)
        if temp is None:
            return None
        group: models.Group = temp
        # first check if no policy
        # if group.policy is None:
        #     return None
        group.policy = policy

    async def async_edit_policy(
        self, group_id: str, source_user: str, policy: PolicyType
    ) -> None:
        """Set policy."""
        temp = await self.async_get_group(group_id)
        if temp is None:
            return None
        group: models.Group = temp
        # check if permissions to edit
        users = await self.async_get_users_having_permission_group(group_id)
        # if users is None:
        #     return None
        source = await self.async_get_user(source_user)
        if source not in users:
            return None

        # if not isinstance(policy, PolicyType):
        #     return None
        group.policy = policy

    async def async_append_group_ids(self, group: str, group_target: str) -> None:
        """RDRA and RH and DMRA and DT assignment and DMDTA."""
        if self._groups is not None:
            self._groups[group].group_ids.append(group_target)
        self._async_schedule_save()
        return None

    async def async_remove_group_ids(self, group: str, group_target: str) -> None:
        """RDRA and RH and DMRA and DT assignment and DMDTA."""
        if self._groups is not None:
            self._groups[group].group_ids.remove(group_target)
        self._async_schedule_save()
        return None

    async def async_append_group_ids_to_users(
        self, user: str, group_target: str
    ) -> None:
        """UA."""
        temp = await self.async_get_group(group_target)
        if not isinstance(temp, models.Group):
            return None
        target: models.Group = temp
        if self._users is not None:
            self._users[user].groups.append(target)
        self._async_schedule_save()
        return None

    async def async_remove_group_ids_to_users(
        self, user: str, group_target: str
    ) -> None:
        """UA."""
        temp = await self.async_get_group(group_target)
        if not isinstance(temp, models.Group):
            return None
        target: models.Group = temp
        if self._users is not None:
            self._users[user].groups.remove(target)
        self._async_schedule_save()
        return None

    async def async_add_decision(
        self, source_user: str, target: str, group: str, action: str
    ) -> None:
        """Add voting process to give access to target."""
        user = await self.async_get_user_by_name(source_user)
        if user is None:
            return None

        dm_users: list[
            models.User
        ] = await self.hass.auth.async_get_users_having_permission_group(group)
        if user not in dm_users:
            return None

        decision: models.Decision = models.Decision(source_user, target, group, action)
        user.decisions.append(decision)
        self._async_schedule_save()

    async def async_get_decision(
        self, source_user: str, target: str, group: str, action: str
    ) -> models.Decision | None:
        """Get decision."""
        user = await self.async_get_user_by_name(source_user)
        if user is None:
            return None
        decisions = user.decisions
        for decision in decisions:
            if (
                decision.source == source_user
                and decision.target == target
                and decision.group == group
                and decision.action == action
            ):
                return decision
        return None

    async def async_vote_decision(
        self,
        source_user: str,
        target: str,
        group: str,
        action: str,
        vote: bool,
        origin_user: str,
    ) -> None:
        """Vote decision."""
        temp = await self.async_get_decision(source_user, target, group, action)
        if temp is None:
            return None
        # check if has right to access (member of DM)
        users = await self.async_get_users_having_permission_group(group)
        origin = await self.async_get_user(origin_user)
        if origin not in users:
            return None

        decision: models.Decision = temp
        if vote:
            decision.approve.append(origin_user)
        else:
            decision.reject.append(origin_user)
        self._async_schedule_save()
        # check result
        await self.perform_action(decision)
        return None

    async def perform_action(self, decision: models.Decision) -> None:
        """Perform action in decision."""
        temp = await self.async_get_users_member_of_dm(decision.group)
        tempa = await self.async_get_dm(decision.group)
        tempad = await self.async_get_dt(decision.group)
        tempada = await self.async_get_group(decision.group)
        if temp is None or tempa is None or tempad is None or tempada is None:
            return None
        group, dman, dtask, cgroup = temp, tempa, tempad, tempada
        # le = len (group)

        match decision.action:
            case "AssignUA":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["AssignUA"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    user = await self.async_get_user(decision.target)
                    if user is None:
                        return None
                    user.groups.append(cgroup)
            case "RevokeUA":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["RevokeUA"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    user = await self.async_get_user(decision.target)
                    if user is None:
                        return None
                    user.groups.remove(cgroup)
            case "AssignRDR":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["AssignRDR"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "RevokeRDR":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["RevokeRDR"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "AssignRH":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["AssignRH"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "RevokeRH":
                ana = dtask.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["RevokeRH"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "AssignDMR":
                ana = dman.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["AssignRDR"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "RevokeDMR":
                ana = dman.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                action_thresh = ana["RevokeDMR"]
                if not isinstance(action_thresh, float):
                    return None
                if action_thresh < len(decision.approve) / len(group):
                    gro = await self.async_get_group(decision.target)
                    if gro is None:
                        return None
                    gro.group_ids.append(decision.group)
            case "EditPolicy":
                ana = cgroup.policy["groups"]
                if not isinstance(ana, dict):
                    return None
                edit_policy = ana["EditPolicy"]
                if not isinstance(edit_policy, float):
                    return None

                if (
                    edit_policy < len(decision.approve) / len(group)
                    and decision.policy is not None
                ):
                    await self.async_edit_policy(
                        decision.target, decision.source, decision.policy
                    )
        self._async_schedule_save()
        return None

    # async def async_decision_checker(
    #     self, source_user: str, target: str, group: str, action: str
    # ) -> None:
    #     """Check decision."""
    #     # self.async_get_decision(source_user, target, action)
    #     # if decision is None:
    #     #     return None
    #     # check decision
    #     # first find all voters
    #     # second compute threshold
    #     # third set result if needed
    #     # forth add group to member if needed
    #     return None

    async def async_get_dt(self, group_id: str) -> models.Group | None:
        """Get DT."""
        groups = await self.async_get_groups()
        for group in groups:
            for gro in group.group_ids:
                if gro == group_id:
                    return group
        return None

    async def async_get_dm(self, group_id: str) -> models.Group | None:
        """Get DM."""
        groups = await self.async_get_groups()
        dtask = ""
        for group in groups:
            for gro in group.group_ids:
                if (
                    gro == group_id
                    and group.name is not None
                    and group.name.startswith("DT")
                ):
                    dtask = gro
                    break
        for group in groups:
            for gro in group.group_ids:
                if (
                    gro == dtask
                    and group.name is not None
                    and group.name.startswith("DM")
                ):
                    return group

        return None

    async def async_activate_user(self, user: models.User) -> None:
        """Activate a user."""
        user.is_active = True
        self._async_schedule_save()

    async def async_deactivate_user(self, user: models.User) -> None:
        """Activate a user."""
        user.is_active = False
        self._async_schedule_save()

    async def async_remove_credentials(self, credentials: models.Credentials) -> None:
        """Remove credentials."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        for user in self._users.values():
            found = None

            for index, cred in enumerate(user.credentials):
                if cred is credentials:
                    found = index
                    break

            if found is not None:
                user.credentials.pop(found)
                break

        self._async_schedule_save()

    async def async_create_refresh_token(
        self,
        user: models.User,
        client_id: str | None = None,
        client_name: str | None = None,
        client_icon: str | None = None,
        token_type: str = models.TOKEN_TYPE_NORMAL,
        access_token_expiration: timedelta = ACCESS_TOKEN_EXPIRATION,
        credential: models.Credentials | None = None,
    ) -> models.RefreshToken:
        """Create a new token for a user."""
        kwargs: dict[str, Any] = {
            "user": user,
            "client_id": client_id,
            "token_type": token_type,
            "access_token_expiration": access_token_expiration,
            "credential": credential,
        }
        if client_name:
            kwargs["client_name"] = client_name
        if client_icon:
            kwargs["client_icon"] = client_icon

        refresh_token = models.RefreshToken(**kwargs)
        user.refresh_tokens[refresh_token.id] = refresh_token

        self._async_schedule_save()
        return refresh_token

    async def async_remove_refresh_token(
        self, refresh_token: models.RefreshToken
    ) -> None:
        """Remove a refresh token."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        for user in self._users.values():
            if user.refresh_tokens.pop(refresh_token.id, None):
                self._async_schedule_save()
                break

    async def async_get_refresh_token(
        self, token_id: str
    ) -> models.RefreshToken | None:
        """Get refresh token by id."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        for user in self._users.values():
            refresh_token = user.refresh_tokens.get(token_id)
            if refresh_token is not None:
                return refresh_token

        return None

    async def async_get_refresh_token_by_token(
        self, token: str
    ) -> models.RefreshToken | None:
        """Get refresh token by token."""
        if self._users is None:
            await self._async_load()
            assert self._users is not None

        found = None

        for user in self._users.values():
            for refresh_token in user.refresh_tokens.values():
                if hmac.compare_digest(refresh_token.token, token):
                    found = refresh_token

        return found

    # at startup load all auth file
    # users/groups/credentials/acces_tokens
    @callback
    def async_log_refresh_token_usage(
        self, refresh_token: models.RefreshToken, remote_ip: str | None = None
    ) -> None:
        """Update refresh token last used information."""
        refresh_token.last_used_at = dt_util.utcnow()
        refresh_token.last_used_ip = remote_ip
        self._async_schedule_save()

    async def _async_load(self) -> None:
        """Load the users."""
        async with self._lock:
            if self._users is not None:
                return
            await self._async_load_task()

    async def _async_load_task(self) -> None:
        """Load the users."""
        dev_reg = dr.async_get(self.hass)
        ent_reg = er.async_get(self.hass)
        data = await self._store.async_load()

        # Make sure that we're not overriding data if 2 loads happened at the
        # same time
        if self._users is not None:
            return

        # check if allowed...?
        self._perm_lookup = perm_lookup = PermissionLookup(ent_reg, dev_reg)

        if data is None or not isinstance(data, dict):
            self._set_defaults()
            return

        users: dict[str, models.User] = OrderedDict()
        groups: dict[str, models.Group] = OrderedDict()
        credentials: dict[str, models.Credentials] = OrderedDict()

        # Soft-migrating data as we load. We are going to make sure we have a
        # read only group and an admin group. There are two states that we can
        # migrate from:
        # 1. Data from a recent version which has a single group without policy
        # 2. Data from old version which has no groups
        has_admin_group = False
        has_user_group = False
        has_read_only_group = False
        group_ids = []
        group_ids_obj = []

        # When creating objects we mention each attribute explicitly. This
        # prevents crashing if user rolls back HA version after a new property
        # was added.

        for group_dict in data.get("groups", []):
            policy: PolicyType | None = None

            if group_dict["id"] == GROUP_ID_ADMIN:
                has_admin_group = True

                name = GROUP_NAME_ADMIN
                policy = system_policies.ADMIN_POLICY
                system_generated = True

            elif group_dict["id"] == GROUP_ID_USER:
                has_user_group = True

                name = GROUP_NAME_USER
                policy = system_policies.USER_POLICY
                system_generated = True

            elif group_dict["id"] == GROUP_ID_READ_ONLY:
                has_read_only_group = True

                name = GROUP_NAME_READ_ONLY
                policy = system_policies.READ_ONLY_POLICY
                system_generated = True

            else:
                name = group_dict["name"]
                policy = None
                policy = group_dict["policy"]
                # if pol is None:
                #     pol = {"enties": {"entity_ids": {}}}
                # policy: PolicyType = pol
                system_generated = False

            if "group_ids" in group_dict:
                group_ids = group_dict["group_ids"]

                for _idx, group_id in enumerate(group_dict["group_ids"]):
                    group_ids_obj.append(groups[group_id])

            if policy is None:
                policy = {"entities": {"entities_ids": None}}
            # We don't want groups without a policy that are not system groups
            # This is part of migrating from state 1
            # elif policy is None:
            #     group_without_policy = group_dict["id"]
            #     continue

            groups[group_dict["id"]] = models.Group(
                id=group_dict["id"],
                name=name,
                policy=policy,
                system_generated=system_generated,
                group_ids=group_ids,
                group_ids_obj=group_ids_obj,
            )

        # If there are no groups, add all existing users to the admin group.
        # This is part of migrating from state 2
        # migrate_users_to_admin_group = not groups and group_without_policy is None

        # If we find a no_policy_group, we need to migrate all users to the
        # admin group. We only do this if there are no other groups, as is
        # the expected state. If not expected state, not marking people admin.
        # This is part of migrating from state 1
        # if groups and group_without_policy is not None:
        #     group_without_policy = None

        # This is part of migrating from state 1 and 2
        if not has_admin_group:
            admin_group = _system_admin_group()
            groups[admin_group.id] = admin_group

        # This is part of migrating from state 1 and 2
        if not has_read_only_group:
            read_only_group = _system_read_only_group()
            groups[read_only_group.id] = read_only_group

        if not has_user_group:
            user_group = _system_user_group()
            groups[user_group.id] = user_group

        for user_dict in data["users"]:
            # Collect the users group.
            user_groups = []
            for group_id in user_dict.get("group_ids", []):
                # This is part of migrating from state 1
                # if group_id == group_without_policy:
                #     group_id = GROUP_ID_ADMIN
                user_groups.append(groups[group_id])

            # This is part of migrating from state 2
            # if not user_dict["system_generated"] and migrate_users_to_admin_group:
            #     user_groups.append(groups[GROUP_ID_ADMIN])

            users[user_dict["id"]] = models.User(
                name=user_dict["name"],
                groups=user_groups,
                id=user_dict["id"],
                is_owner=user_dict["is_owner"],
                is_active=user_dict["is_active"],
                system_generated=user_dict["system_generated"],
                perm_lookup=perm_lookup,
                # New in 2021.11
                local_only=user_dict.get("local_only", False),
            )

        for cred_dict in data["credentials"]:
            credential = models.Credentials(
                id=cred_dict["id"],
                is_new=False,
                auth_provider_type=cred_dict["auth_provider_type"],
                auth_provider_id=cred_dict["auth_provider_id"],
                data=cred_dict["data"],
            )
            credentials[cred_dict["id"]] = credential
            users[cred_dict["user_id"]].credentials.append(credential)

        for rt_dict in data["refresh_tokens"]:
            # Filter out the old keys that don't have jwt_key (pre-0.76)
            if "jwt_key" not in rt_dict:
                continue

            created_at = dt_util.parse_datetime(rt_dict["created_at"])
            if created_at is None:
                getLogger(__name__).error(
                    (
                        "Ignoring refresh token %(id)s with invalid created_at "
                        "%(created_at)s for user_id %(user_id)s"
                    ),
                    rt_dict,
                )
                continue

            if (token_type := rt_dict.get("token_type")) is None:
                if rt_dict["client_id"] is None:
                    token_type = models.TOKEN_TYPE_SYSTEM
                else:
                    token_type = models.TOKEN_TYPE_NORMAL

            # old refresh_token don't have last_used_at (pre-0.78)
            if last_used_at_str := rt_dict.get("last_used_at"):
                last_used_at = dt_util.parse_datetime(last_used_at_str)
            else:
                last_used_at = None

            token = models.RefreshToken(
                id=rt_dict["id"],
                user=users[rt_dict["user_id"]],
                client_id=rt_dict["client_id"],
                # use dict.get to keep backward compatibility
                client_name=rt_dict.get("client_name"),
                client_icon=rt_dict.get("client_icon"),
                token_type=token_type,
                created_at=created_at,
                access_token_expiration=timedelta(
                    seconds=rt_dict["access_token_expiration"]
                ),
                token=rt_dict["token"],
                jwt_key=rt_dict["jwt_key"],
                last_used_at=last_used_at,
                last_used_ip=rt_dict.get("last_used_ip"),
                version=rt_dict.get("version"),
            )
            if "credential_id" in rt_dict:
                token.credential = credentials.get(rt_dict["credential_id"])
            users[rt_dict["user_id"]].refresh_tokens[token.id] = token

        for decision_dict in data["decisions"]:
            decision = models.Decision(
                decision_dict["source"],
                decision_dict["target"],
                decision_dict["group"],
                decision_dict["action"],
                decision_dict["reject"],
                decision_dict["approve"],
                decision_dict["result"],
            )

            for user in users:
                if users[user].name == decision_dict["source"]:
                    users[user].decisions.append(decision)
        self._groups = groups
        self._users = users

    @callback
    def _async_schedule_save(self) -> None:
        """Save users."""
        if self._users is None:
            return

        self._store.async_delay_save(self._data_to_save, 1)

    @callback
    def _async_schedule_save_groups(self) -> None:
        """Save groups."""
        if self._groups is None:
            return

        self._store.async_delay_save(self._data_to_save, 1)

    @callback
    def _data_to_save(self) -> dict[str, list[dict[str, Any]]]:
        """Return the data to store."""
        assert self._users is not None
        assert self._groups is not None

        users = [
            {
                "id": user.id,
                "group_ids": [group.id for group in user.groups],
                "is_owner": user.is_owner,
                "is_active": user.is_active,
                "name": user.name,
                "system_generated": user.system_generated,
                "local_only": user.local_only,
            }
            for user in self._users.values()
        ]

        groups = []
        for group in self._groups.values():
            g_dict: dict[str, Any] = {
                "id": group.id,
                # Name not read for sys groups. Kept here for backwards compat
                "name": group.name,
            }

            if not group.system_generated:
                g_dict["policy"] = group.policy
                g_dict["group_ids"] = group.group_ids

            groups.append(g_dict)

        credentials = [
            {
                "id": credential.id,
                "user_id": user.id,
                "auth_provider_type": credential.auth_provider_type,
                "auth_provider_id": credential.auth_provider_id,
                "data": credential.data,
            }
            for user in self._users.values()
            for credential in user.credentials
        ]

        refresh_tokens = [
            {
                "id": refresh_token.id,
                "user_id": user.id,
                "client_id": refresh_token.client_id,
                "client_name": refresh_token.client_name,
                "client_icon": refresh_token.client_icon,
                "token_type": refresh_token.token_type,
                "created_at": refresh_token.created_at.isoformat(),
                "access_token_expiration": (
                    refresh_token.access_token_expiration.total_seconds()
                ),
                "token": refresh_token.token,
                "jwt_key": refresh_token.jwt_key,
                "last_used_at": refresh_token.last_used_at.isoformat()
                if refresh_token.last_used_at
                else None,
                "last_used_ip": refresh_token.last_used_ip,
                "credential_id": refresh_token.credential.id
                if refresh_token.credential
                else None,
                "version": refresh_token.version,
            }
            for user in self._users.values()
            for refresh_token in user.refresh_tokens.values()
        ]

        decisions = [
            {
                "source": decision.source,
                "target": decision.target,
                "group": decision.group,
                "action": decision.action,
                "reject": decision.reject,
                "approve": decision.approve,
                "result": decision.result,
            }
            for user in self._users.values()
            for decision in user.decisions
        ]

        return {
            "users": users,
            "groups": groups,
            "credentials": credentials,
            "refresh_tokens": refresh_tokens,
            "decisions": decisions,
        }

    def _set_defaults(self) -> None:
        """Set default values for auth store."""
        self._users = OrderedDict()

        groups: dict[str, models.Group] = OrderedDict()
        admin_group = _system_admin_group()
        groups[admin_group.id] = admin_group
        user_group = _system_user_group()
        groups[user_group.id] = user_group
        read_only_group = _system_read_only_group()
        groups[read_only_group.id] = read_only_group
        self._groups = groups


def _system_admin_group() -> models.Group:
    """Create system admin group."""
    return models.Group(
        name=GROUP_NAME_ADMIN,
        id=GROUP_ID_ADMIN,
        policy=system_policies.ADMIN_POLICY,
        system_generated=True,
    )


def _system_user_group() -> models.Group:
    """Create system user group."""
    return models.Group(
        name=GROUP_NAME_USER,
        id=GROUP_ID_USER,
        policy=system_policies.USER_POLICY,
        system_generated=True,
    )


def _system_read_only_group() -> models.Group:
    """Create read only group."""
    return models.Group(
        name=GROUP_NAME_READ_ONLY,
        id=GROUP_ID_READ_ONLY,
        policy=system_policies.READ_ONLY_POLICY,
        system_generated=True,
    )
