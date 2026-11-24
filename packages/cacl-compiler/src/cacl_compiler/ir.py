import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .ast_nodes import Effect, PredicateKind, Scope
from .permissions import ALL_ATOMIC_MASK, mask_to_atomic_names

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=UTC)


def format_utc_rfc3339(dt: datetime) -> str:
    utc = dt.astimezone(UTC)
    if utc.microsecond == 0:
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"


def datetime_to_epoch_us(dt: datetime) -> int:
    if dt.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    delta = dt.astimezone(UTC) - _EPOCH_UTC
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def epoch_us_to_datetime(epoch_us: int) -> datetime:
    return _EPOCH_UTC + timedelta(microseconds=epoch_us)


def _encode_timestamp(
    dt: datetime | None,
    mode: Literal["rfc3339", "datetime", "epoch_us"],
) -> str | datetime | int | None:
    if dt is None:
        return None
    if mode == "rfc3339":
        return format_utc_rfc3339(dt)
    if mode == "datetime":
        return dt.astimezone(UTC)
    if mode == "epoch_us":
        return datetime_to_epoch_us(dt)
    raise ValueError(f"Unsupported timestamp_mode: {mode!r}")


def _decode_timestamp(value: str | datetime | int | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Stored datetime timestamp must be timezone-aware")
        return value.astimezone(UTC)
    if isinstance(value, int) and not isinstance(value, bool):
        return epoch_us_to_datetime(value)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError(f"Timestamp string must include timezone offset: {value!r}")
        return parsed.astimezone(UTC)
    raise TypeError(f"Unsupported timestamp representation: {type(value)!r}")


@dataclass(frozen=True, slots=True)
class ConditionAtom:
    """Single literal in a DNF conjunction (maps 1:1 to `ace_condition_atoms`)."""

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
    """Conjunction of atoms (maps 1:1 to `ace_condition_groups`). Empty tuple == TRUE (any)."""

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
        from_key = (
            (0, 0)
            if self.valid_from is None
            else (1, datetime_to_epoch_us(self.valid_from))
        )
        until_key = (
            (0, 0)
            if self.valid_until is None
            else (1, datetime_to_epoch_us(self.valid_until))
        )
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

    def next_transition_after(self, at_utc: datetime) -> datetime | None:
        """Earliest temporal validity boundary strictly after ``at_utc``."""
        if at_utc.tzinfo is None:
            raise ValueError("at_utc must be timezone-aware")
        ref = at_utc.astimezone(UTC)
        candidates = [
            ts for ts in (self.valid_from, self.valid_until) if ts is not None and ts > ref
        ]
        return min(candidates) if candidates else None

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

    @property
    def allow_mask_union(self) -> int:
        mask = 0
        for rule in self.rules:
            if rule.effect is Effect.ALLOW:
                mask |= rule.permission_mask
        return mask

    @property
    def deny_mask_union(self) -> int:
        mask = 0
        for rule in self.rules:
            if rule.effect is Effect.DENY:
                mask |= rule.permission_mask
        return mask

    def canonical_rules(self) -> tuple[CompiledRule, ...]:
        """Return rules in deterministic canonical order."""
        return tuple(sorted(self.rules, key=lambda r: r.canonical_sort_key()))

    def canonicalize(self) -> CompiledPolicy:
        """Return a semantically equivalent policy with deduplicated, canonically ordered rules."""
        by_semantic: dict[tuple, CompiledRule] = {}
        for rule in sorted(self.rules, key=lambda r: r.canonical_sort_key()):
            key = rule.semantic_key()
            existing = by_semantic.get(key)
            if existing is None or (existing.remark is None and rule.remark is not None):
                by_semantic[key] = rule
        return CompiledPolicy(
            inherit=self.inherit,
            rules=tuple(sorted(by_semantic.values(), key=lambda r: r.canonical_sort_key())),
        )

    def next_transition_after(self, at_utc: datetime) -> datetime | None:
        """Earliest rule activation/expiration timestamp strictly after ``at_utc``."""
        earliest: datetime | None = None
        for rule in self.rules:
            nxt = rule.next_transition_after(at_utc)
            if nxt is not None and (earliest is None or nxt < earliest):
                earliest = nxt
        return earliest

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
        canonical = json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": "CEP-0002",
            "inherit": self.inherit,
            "rules": [r.to_dict() for r in self.rules],
        }

    def to_ssot_rows(
        self,
        node_id: str,
        *,
        timestamp_mode: Literal["rfc3339", "datetime", "epoch_us"] = "rfc3339",
    ) -> dict[str, list[dict[str, Any]]]:
        """Export relational SSOT rows ready for direct SQLAlchemy/SQL insertion."""
        aces: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        atoms: list[dict[str, Any]] = []

        group_seq = 1
        atom_seq = 1
        for ace_idx, rule in enumerate(self.rules, start=1):
            aces.append({
                "ace_local_id": ace_idx,
                "node_id": node_id,
                "effect": rule.effect.value,
                "permission_mask": rule.permission_mask,
                "scope": rule.scope.value,
                "valid_from": _encode_timestamp(rule.valid_from, timestamp_mode),
                "valid_until": _encode_timestamp(rule.valid_until, timestamp_mode),
                "remark": rule.remark,
            })
            for clause in rule.dnf_clauses:
                gid = group_seq
                group_seq += 1
                groups.append({
                    "group_local_id": gid,
                    "ace_local_id": ace_idx,
                })
                for atom in clause.atoms:
                    atoms.append({
                        "atom_local_id": atom_seq,
                        "group_local_id": gid,
                        "predicate_kind": atom.kind.value,
                        "predicate_value": atom.value,
                        "is_negated": atom.negated,
                    })
                    atom_seq += 1

        return {
            "node_policy": [{"node_id": node_id, "inherit": self.inherit}],
            "aces": aces,
            "ace_condition_groups": groups,
            "ace_condition_atoms": atoms,
        }

    @classmethod
    def from_ssot_rows(
        cls,
        rows: Mapping[str, Sequence[Mapping[str, Any]]],
        *,
        node_id: str | None = None,
    ) -> CompiledPolicy:
        """Reconstruct a CompiledPolicy from relational SSOT table rows."""
        node_policies = rows.get("node_policy", ())
        inherit = True
        if node_policies:
            if node_id is None:
                inherit = bool(node_policies[0]["inherit"])
            else:
                for entry in node_policies:
                    if entry.get("node_id") == node_id:
                        inherit = bool(entry["inherit"])
                        break

        atoms_by_group: dict[Any, list[ConditionAtom]] = {}
        for row in rows.get("ace_condition_atoms", ()):
            gid = row.get("group_local_id", row.get("clause_id"))
            atoms_by_group.setdefault(gid, []).append(
                ConditionAtom(
                    kind=PredicateKind(row["predicate_kind"]),
                    value=str(row["predicate_value"]),
                    negated=bool(row.get("is_negated", False)),
                )
            )

        groups_by_ace: dict[Any, list[DNFClause]] = {}
        for row in rows.get("ace_condition_groups", ()):
            ace_id = row.get("ace_local_id", row.get("rule_id"))
            gid = row.get("group_local_id", row.get("id"))
            clause_atoms = tuple(
                sorted(atoms_by_group.get(gid, ()), key=lambda a: a.sort_key())
            )
            groups_by_ace.setdefault(ace_id, []).append(DNFClause(atoms=clause_atoms))

        compiled_rules: list[CompiledRule] = []
        for row in rows.get("aces", ()):
            if node_id is not None and row.get("node_id") != node_id:
                continue
            ace_id = row.get("ace_local_id", row.get("id"))
            clauses = tuple(
                sorted(
                    groups_by_ace.get(ace_id, ()),
                    key=lambda c: tuple(a.sort_key() for a in c.atoms),
                )
            )
            compiled_rules.append(
                CompiledRule(
                    effect=Effect(row["effect"]),
                    permission_mask=int(row["permission_mask"]),
                    scope=Scope(row["scope"]),
                    dnf_clauses=clauses,
                    valid_from=_decode_timestamp(row.get("valid_from")),
                    valid_until=_decode_timestamp(row.get("valid_until")),
                    remark=row.get("remark"),
                )
            )

        return cls(inherit=inherit, rules=tuple(compiled_rules))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompiledPolicy:
        return cls(
            inherit=bool(data["inherit"]),
            rules=tuple(CompiledRule.from_dict(r) for r in data.get("rules", [])),
        )
