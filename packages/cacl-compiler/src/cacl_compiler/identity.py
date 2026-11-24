import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

_RFC9562_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)


def parse_canonical_uuid(raw: str) -> UUID | None:
    """Parse a strict 36-char hyphenated RFC 9562 UUID (version/variant agnostic)."""
    if not _RFC9562_UUID_RE.match(raw):
        return None
    return UUID(raw)


@runtime_checkable
class PrincipalResolver(Protocol):
    """Optional identity directory contract for existence checks and `#` comment annotations."""

    def resolve_uuid_to_username(self, user_id: UUID) -> str | None:
        """Reverse-resolve an immutable user UUID to a human username for `#` comment annotations."""
        ...

    def user_exists(self, user_id: UUID) -> bool:
        """Check whether the user UUID exists in the directory."""
        ...

    def group_exists(self, group_id: str) -> bool | None:
        """Optional group existence check. Return None if group validation is disabled."""
        ...

    def perm_exists(self, perm_name: str) -> bool | None:
        """Optional system capability check. Return None if capability validation is disabled."""
        ...


@runtime_checkable
class BatchPrincipalResolver(PrincipalResolver, Protocol):
    """Optional batch lookup extension preventing N+1 directory queries."""

    def existing_users(self, user_ids: set[UUID]) -> set[UUID]:
        """Return the subset of ``user_ids`` that exist in the directory."""
        ...

    def existing_groups(self, group_ids: set[str]) -> set[str] | None:
        """Return the subset of existing ``group_ids``, or None if group validation is disabled."""
        ...

    def existing_perms(self, perm_names: set[str]) -> set[str] | None:
        """Return the subset of registered ``perm_names``, or None if capability validation is disabled."""
        ...

    def resolve_uuids_to_usernames(self, user_ids: set[UUID]) -> dict[UUID, str]:
        """Batch-resolve user UUIDs to usernames for `#` comment annotations."""
        ...


@dataclass(frozen=True, slots=True)
class UserDirectoryEntry:
    id: UUID
    username: str


class InMemoryPrincipalResolver:
    """Reference in-memory directory for optional existence checks and annotated decompilation."""

    def __init__(
        self,
        users: list[UserDirectoryEntry] | None = None,
        groups: set[str] | None = None,
        perms: set[str] | None = None,
    ) -> None:
        self._by_uuid: dict[UUID, str] = {entry.id: entry.username for entry in users or []}
        self._groups = groups
        self._perms = perms

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InMemoryPrincipalResolver:
        """Load directory snapshot from JSON dict:
        {
          "users": [{"id": "550e8400-...", "username": "alice"}],
          "groups": ["engineering", "reviewers"],
          "perms": ["audit.read_history"]
        }
        """
        users = [
            UserDirectoryEntry(id=UUID(item["id"]), username=item["username"])
            for item in data.get("users", [])
        ]
        groups = (
            set(data["groups"])
            if "groups" in data and data["groups"] is not None
            else None
        )
        perms = (
            set(data["perms"])
            if "perms" in data and data["perms"] is not None
            else None
        )
        return cls(users=users, groups=groups, perms=perms)

    def resolve_uuid_to_username(self, user_id: UUID) -> str | None:
        return self._by_uuid.get(user_id)

    def user_exists(self, user_id: UUID) -> bool:
        return user_id in self._by_uuid

    def group_exists(self, group_id: str) -> bool | None:
        if self._groups is None:
            return None
        return group_id in self._groups

    def perm_exists(self, perm_name: str) -> bool | None:
        if self._perms is None:
            return None
        return perm_name in self._perms

    def existing_users(self, user_ids: set[UUID]) -> set[UUID]:
        return {uid for uid in user_ids if uid in self._by_uuid}

    def existing_groups(self, group_ids: set[str]) -> set[str] | None:
        if self._groups is None:
            return None
        return group_ids & self._groups

    def existing_perms(self, perm_names: set[str]) -> set[str] | None:
        if self._perms is None:
            return None
        return perm_names & self._perms

    def resolve_uuids_to_usernames(self, user_ids: set[UUID]) -> dict[UUID, str]:
        return {uid: self._by_uuid[uid] for uid in user_ids if uid in self._by_uuid}
