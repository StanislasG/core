"""Permissions for Home Assistant."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import voluptuous as vol

from .const import CAT_ENTITIES
from .entities import ENTITY_POLICY_SCHEMA, compile_entities
from .merge import merge_policies
from .models import PermissionLookup
from .types import PolicyType
from .util import test_all

POLICY_SCHEMA = vol.Schema({vol.Optional(CAT_ENTITIES): ENTITY_POLICY_SCHEMA})

__all__ = [
    "POLICY_SCHEMA",
    "merge_policies",
    "PermissionLookup",
    "PolicyType",
    "AbstractPermissions",
    "PolicyPermissions",
    "OwnerPermissions",
]


class AbstractPermissions:
    """Default permissions class."""

    _cached_entity_func: Callable[[str, str], bool] | None = None
    # _cached_group_func: Callable[[str], bool] | None = None

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        raise NotImplementedError

    def _group_func(self, group_id: str) -> bool:
        """Return a function that can test entity access."""
        raise NotImplementedError

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        raise NotImplementedError

    def check_entity(self, entity_id: str, key: str) -> bool:
        """Check if we can access entity."""
        if (entity_func := self._cached_entity_func) is None:
            entity_func = self._cached_entity_func = self._entity_func()

        return entity_func(entity_id, key)

    def check_group(self, group_id: str) -> bool:
        """Check if we can access entity."""
        # if (group_func := self._cached_group_func) is None:
        #     group_func = self._cached_group_func = self._group_func()

        return self._group_func(group_id)


class PolicyPermissions(AbstractPermissions):
    """Handle permissions."""

    def __init__(self, policy: PolicyType, perm_lookup: PermissionLookup) -> None:
        """Initialize the permission class."""
        self._policy = policy
        self._perm_lookup = perm_lookup

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return test_all(self._policy.get(CAT_ENTITIES), key)

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return compile_entities(self._policy.get(CAT_ENTITIES), self._perm_lookup)

    def __eq__(self, other: Any) -> bool:
        """Equals check."""
        return isinstance(other, PolicyPermissions) and other._policy == self._policy

    def _group_func(self, group_id: str) -> bool:
        """Return a function that can test entity access."""
        # check for groups in _policy
        return self.check_group(group_id)


class _OwnerPermissions(AbstractPermissions):
    """Owner permissions."""

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return True

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return lambda entity_id, key: True


OwnerPermissions = _OwnerPermissions()
