"""System policies."""
from .const import CAT_ENTITIES, POLICY_READ, SUBCAT_ALL
from .types import PolicyType

ADMIN_POLICY: PolicyType = {CAT_ENTITIES: True}

USER_POLICY: PolicyType = {CAT_ENTITIES: True}

READ_ONLY_POLICY: PolicyType = {CAT_ENTITIES: {SUBCAT_ALL: {POLICY_READ: True}}}
