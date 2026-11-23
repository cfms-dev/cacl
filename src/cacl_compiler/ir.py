import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .ast_nodes import Effect, PredicateKind, Scope
from .permissions import mask_to_atomic_names


def format_utc_rfc3339(dt: datetime) -> str:
    utc = dt.astimezone(UTC)
    if utc.microsecond == 0:
        return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"


@dataclass(frozen=True, slots=True)
class ConditionAtom:
    """Single literal in a DNF conjunction (maps 1:1 to `ace_condition_atoms`)."""

    kind: PredicateKind
    value: str  # Canonical lowercase UUID for USER; string ID for GROUP/PERM
    negated: bool = False
    resolved: bool = True  # False only if offline symbolic username mode was enabled

    def sort_key(self) -> tuple[str, str, bool]:
        return (self.kind.value, self.value, self.negated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "is_negated": self.negated,
            "resolved": self.resolved,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConditionAtom:
        return cls(
            kind=PredicateKind(data["kind"]),
            value=data["value"],
            negated=bool(data.get("is_negated", False)),
            resolved=bool(data.get("resolved", True)),
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
        v_from = (
            datetime.fromisoformat(
                data["valid_from"]
            ).astimezone(UTC)
            if data.get("valid_from")
            else None
        )
        v_until = (
            datetime.fromisoformat(
                data["valid_until"]
            ).astimezone(UTC)
            if data.get("valid_until")
            else None
        )
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
    ssot_ready: bool = True

    def fingerprint(self) -> str:
        """Deterministic SHA-256 fingerprint of the compiled policy semantics."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": "CEP-0002",
            "inherit": self.inherit,
            "ssot_ready": self.ssot_ready,
            "rules": [r.to_dict() for r in self.rules],
        }

    def to_ssot_rows(self, node_id: str) -> dict[str, list[dict[str, Any]]]:
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
                "valid_from": format_utc_rfc3339(rule.valid_from)
                if rule.valid_from
                else None,
                "valid_until": format_utc_rfc3339(rule.valid_until)
                if rule.valid_until
                else None,
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
    def from_dict(cls, data: dict[str, Any]) -> CompiledPolicy:
        return cls(
            inherit=bool(data["inherit"]),
            rules=tuple(CompiledRule.from_dict(r) for r in data.get("rules", [])),
            ssot_ready=bool(data.get("ssot_ready", True)),
        )
