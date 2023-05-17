"""Common code for permissions."""
from collections.abc import Mapping

# MyPy doesn't support recursion yet. So writing it out as far as we need.

ValueType = (
    # Example: entities.all = { read: true, control: true }
    Mapping[str, bool]
    | bool
    | list[str]
    | None
)

# Example: entities.domains = { light: … }
SubCategoryDict = Mapping[str, ValueType]

SubCategoryType = SubCategoryDict | bool | None

CategoryType = (
    # Example: entities.domains
    Mapping[str, SubCategoryType]
    # Example: entities.all
    | Mapping[str, ValueType]
    | bool
    | None
)

# GroupList = Mapping[str, list[str]]
# Example: { entities: … } & {group_ids: []}
PolicyType = Mapping[str, CategoryType]  # | GroupList | None
