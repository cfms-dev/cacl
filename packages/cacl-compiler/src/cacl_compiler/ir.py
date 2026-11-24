import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .ast_nodes import Effect, PredicateKind, Scope
from .permissions import ALL_ATOMIC_MASK, mask_to_atomic_names

_MIN_UTC = datetime.min.replace(tzinfo=UTC)


def format_utc_rfc3339(dt: datetime) -> str:
    utc = dt.astimezone(UTC)
    if utc.microsecond == 0:
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"


def _decode_timestamp(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Stored datetime timestamp must be timezone-aware")
        return value.astimezone(UTC)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError(
                f"Timestamp string must include timezone offset: {value!r}"
            )
        return parsed.astimezone(UTC)
    raise TypeError(f"Unsupported timestamp representation: {type(value)!r}")


@dataclass(frozen=True, slots=True)
class ConditionAtom:
    """Single literal in a DNF conjunction."""

    kind: PredicateKind
    value: str  # Canonical lowercase UUID for USER; string ID for GROUP/PERM
    negated: bool = False

    def sort_key(self) -> tuple[str, str, bool]:
        return (self.kind.value, self.value, self.negated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "is_negated": self.negated,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConditionAtom:
        return cls(
            kind=PredicateKind(data["kind"]),
            value=data["value"],
            negated=bool(data.get("is_negated", False)),
        )


@dataclass(frozen=True, slots=True)
class DNFClause:
    """Conjunction of atoms in a DNF expression. Empty tuple == TRUE (any)."""

    atoms: tuple[ConditionAtom, ...]

    @property
    def is_tautology(self) -> bool:
        return len(self.atoms) == 0

    def to_dict(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self.atoms]

    @classmethod
    def from_dict(cls, data: list[dict[str, Any]]) -> DNFClause:
        return cls(atoms=tuple(ConditionAtom.from_dict(item) for item in data))


@dataclass(frozen=True, slots=True)
class CompiledRule:
    effect: Effect
    permission_mask: int
    scope: Scope
    dnf_clauses: tuple[DNFClause, ...]
    valid_from: datetime | None
    valid_until: datetime | None
    remark: str | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.permission_mask, bool)
            or not isinstance(self.permission_mask, int)
            or self.permission_mask <= 0
            or self.permission_mask > ALL_ATOMIC_MASK
        ):
            raise ValueError(
                f"permission_mask must be a non-empty 21-bit mask (1..0x{ALL_ATOMIC_MASK:06x}), "
                f"got {self.permission_mask!r}"
            )
        if self.valid_from is not None:
            if self.valid_from.tzinfo is None:
                raise ValueError("valid_from must be timezone-aware")
            object.__setattr__(self, "valid_from", self.valid_from.astimezone(UTC))
        if self.valid_until is not None:
            if self.valid_until.tzinfo is None:
                raise ValueError("valid_until must be timezone-aware")
            object.__setattr__(self, "valid_until", self.valid_until.astimezone(UTC))
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_from >= self.valid_until
        ):
            raise ValueError("valid_from must be strictly earlier than valid_until")

    @property
    def is_unconditional(self) -> bool:
        return len(self.dnf_clauses) == 1 and self.dnf_clauses[0].is_tautology

    @property
    def is_unsatisfiable(self) -> bool:
        return len(self.dnf_clauses) == 0

    def semantic_key(self) -> tuple:
        """Canonical key for duplicate rule detection (ignores remark)."""
        return (
            self.effect.value,
            self.permission_mask,
            self.scope.value,
            self.dnf_clauses,
            self.valid_from,
            self.valid_until,
        )

    def canonical_sort_key(self, *, include_remark: bool = True) -> tuple:
        """Deterministic total sort key for order-independent canonicalization."""
        clauses_key = tuple(
            tuple(a.sort_key() for a in clause.atoms) for clause in self.dnf_clauses
        )
        from_key = (0, _MIN_UTC) if self.valid_from is None else (1, self.valid_from)
        until_key = (0, _MIN_UTC) if self.valid_until is None else (1, self.valid_until)
        base = (
            0 if self.effect is Effect.DENY else 1,
            self.scope.value,
            self.permission_mask,
            clauses_key,
            from_key,
            until_key,
        )
        if include_remark:
            return (*base, self.remark is not None, self.remark or "")
        return base

    def referenced_principals(
        self,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
        """Return (user_uuids, group_ids, perm_names) referenced in this rule."""
        users: set[str] = set()
        groups: set[str] = set()
        perms: set[str] = set()
        for clause in self.dnf_clauses:
            for atom in clause.atoms:
                if atom.kind is PredicateKind.USER:
                    users.add(atom.value)
                elif atom.kind is PredicateKind.GROUP:
                    groups.add(atom.value)
                elif atom.kind is PredicateKind.PERM:
                    perms.add(atom.value)
        return frozenset(users), frozenset(groups), frozenset(perms)

    def _canonical_fingerprint_dict(self, *, include_remark: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "effect": self.effect.value,
            "permission_mask": self.permission_mask,
            "scope": self.scope.value,
            "dnf_clauses": [clause.to_dict() for clause in self.dnf_clauses],
            "valid_from": format_utc_rfc3339(self.valid_from)
            if self.valid_from
            else None,
            "valid_until": format_utc_rfc3339(self.valid_until)
            if self.valid_until
            else None,
        }
        if include_remark:
            payload["remark"] = self.remark
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "permission_mask": self.permission_mask,
            "permission_mask_hex": f"0x{self.permission_mask:06x}",
            "operations": mask_to_atomic_names(self.permission_mask),
            "scope": self.scope.value,
            "is_unconditional": self.is_unconditional,
            "dnf_clauses": [clause.to_dict() for clause in self.dnf_clauses],
            "valid_from": format_utc_rfc3339(self.valid_from)
            if self.valid_from
            else None,
            "valid_until": format_utc_rfc3339(self.valid_until)
            if self.valid_until
            else None,
            "remark": self.remark,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompiledRule:
        v_from = _decode_timestamp(data.get("valid_from"))
        v_until = _decode_timestamp(data.get("valid_until"))
        return cls(
            effect=Effect(data["effect"]),
            permission_mask=int(data["permission_mask"]),
            scope=Scope(data["scope"]),
            dnf_clauses=tuple(DNFClause.from_dict(c) for c in data["dnf_clauses"]),
            valid_from=v_from,
            valid_until=v_until,
            remark=data.get("remark"),
        )


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    inherit: bool
    rules: tuple[CompiledRule, ...]

    def canonical_rules(self) -> tuple[CompiledRule, ...]:
        """Return rules in deterministic canonical order."""
        return tuple(sorted(self.rules, key=lambda r: r.canonical_sort_key()))

    def canonicalize(self) -> CompiledPolicy:
        """Return a semantically equivalent policy with deduplicated, canonically ordered rules."""
        by_semantic: dict[tuple, CompiledRule] = {}
        for rule in sorted(self.rules, key=lambda r: r.canonical_sort_key()):
            key = rule.semantic_key()
            existing = by_semantic.get(key)
            if existing is None or (
                existing.remark is None and rule.remark is not None
            ):
                by_semantic[key] = rule
        return CompiledPolicy(
            inherit=self.inherit,
            rules=tuple(
                sorted(by_semantic.values(), key=lambda r: r.canonical_sort_key())
            ),
        )

    def referenced_users(self) -> frozenset[str]:
        return frozenset(
            atom.value
            for rule in self.rules
            for clause in rule.dnf_clauses
            for atom in clause.atoms
            if atom.kind is PredicateKind.USER
        )

    def referenced_groups(self) -> frozenset[str]:
        return frozenset(
            atom.value
            for rule in self.rules
            for clause in rule.dnf_clauses
            for atom in clause.atoms
            if atom.kind is PredicateKind.GROUP
        )

    def referenced_perms(self) -> frozenset[str]:
        return frozenset(
            atom.value
            for rule in self.rules
            for clause in rule.dnf_clauses
            for atom in clause.atoms
            if atom.kind is PredicateKind.PERM
        )

    def fingerprint(self, *, include_remarks: bool = True) -> str:
        """Deterministic, rule-order-independent SHA-256 fingerprint."""
        ordered = sorted(
            self.rules,
            key=lambda r: r.canonical_sort_key(include_remark=include_remarks),
        )
        canonical_payload = {
            "spec": "CEP-0002",
            "inherit": self.inherit,
            "rules": [
                r._canonical_fingerprint_dict(include_remark=include_remarks)
                for r in ordered
            ],
        }
        canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": "CEP-0002",
            "inherit": self.inherit,
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompiledPolicy:
        return cls(
            inherit=bool(data["inherit"]),
            rules=tuple(CompiledRule.from_dict(r) for r in data.get("rules", [])),
        )
