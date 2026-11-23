from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID


def parse_canonical_uuid(raw: str) -> UUID | None:
    """Parse a strict RFC 4122 UUID string; returns None if invalid."""
    text = raw.strip()
    if len(text) != 36:
        # Reject 32-char hex or braced variants as non-canonical unless explicitly normalized;
        # remove this check if you wish to accept compact 32-hex UUIDs.
        return None
    try:
        parsed = UUID(text)
    except ValueError:
        return None
    return parsed if str(parsed) == text.lower() else None


@runtime_checkable
class PrincipalResolver(Protocol):
    """Dependency-injection contract bridging standalone CACL with an identity directory."""

    def resolve_username_to_uuid(self, username: str) -> UUID | None:
        """Resolve a human username (e.g. 'alice') to its immutable user UUID."""
        ...

    def resolve_uuid_to_username(self, user_id: UUID) -> str | None:
        """Reverse-resolve an immutable user UUID back to its current username for decompilation."""
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


@dataclass(frozen=True, slots=True)
class UserDirectoryEntry:
    id: UUID
    username: str


class InMemoryPrincipalResolver:
    """Reference in-memory resolver suitable for CLI fixtures, tests, and local tooling."""

    def __init__(
        self,
        users: list[UserDirectoryEntry] | None = None,
        groups: set[str] | None = None,
        perms: set[str] | None = None,
        case_sensitive_username: bool = True,
    ) -> None:
        self._case_sensitive = case_sensitive_username
        self._by_uuid: dict[UUID, str] = {}
        self._by_username: dict[str, UUID] = {}
        for entry in users or []:
            key = entry.username if case_sensitive_username else entry.username.lower()
            if key in self._by_username and self._by_username[key] != entry.id:
                raise ValueError(f"Duplicate username mapping for {entry.username!r}")
            self._by_uuid[entry.id] = entry.username
            self._by_username[key] = entry.id
        self._groups = groups
        self._perms = perms

    @classmethod
    def from_dict(cls, data: dict) -> InMemoryPrincipalResolver:
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
        return cls(
            users=users,
            groups=groups,
            perms=perms,
            case_sensitive_username=data.get("case_sensitive_username", True),
        )

    def resolve_username_to_uuid(self, username: str) -> UUID | None:
        key = username if self._case_sensitive else username.lower()
        return self._by_username.get(key)

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
