from dataclasses import dataclass

from .ast_nodes import PredicateKind
from .ir import ConditionAtom, DNFClause


class DNFComplexityError(Exception):
    """Raised when DNF expansion exceeds the safety clause limit."""


# --- Intermediate Boolean IR (post-resolution, pre-DNF) ---


class BoolIR:
    pass


@dataclass(frozen=True, slots=True)
class BoolConst(BoolIR):
    value: bool


@dataclass(frozen=True, slots=True)
class BoolAtom(BoolIR):
    atom: ConditionAtom


@dataclass(frozen=True, slots=True)
class BoolNot(BoolIR):
    operand: BoolIR


@dataclass(frozen=True, slots=True)
class BoolAnd(BoolIR):
    left: BoolIR
    right: BoolIR


@dataclass(frozen=True, slots=True)
class BoolOr(BoolIR):
    left: BoolIR
    right: BoolIR


@dataclass(frozen=True, slots=True)
class DNFResult:
    clauses: tuple[DNFClause, ...]
    had_user_exclusivity_contradiction: bool = False
    was_absorbed_by_any: bool = False
    simplified_to_tautology: bool = False


def _to_nnf(node: BoolIR, negated: bool = False) -> BoolIR:
    """Push negations down to atoms via De Morgan's laws and double-negation elimination."""
    if isinstance(node, BoolConst):
        return BoolConst(not node.value if negated else node.value)
    if isinstance(node, BoolAtom):
        atom = node.atom
        return BoolAtom(
            ConditionAtom(
                kind=atom.kind,
                value=atom.value,
                negated=(not atom.negated if negated else atom.negated),
            )
        )
    if isinstance(node, BoolNot):
        return _to_nnf(node.operand, negated=not negated)
    if isinstance(node, BoolAnd):
        if negated:
            return BoolOr(_to_nnf(node.left, True), _to_nnf(node.right, True))
        return BoolAnd(_to_nnf(node.left, False), _to_nnf(node.right, False))
    if isinstance(node, BoolOr):
        if negated:
            return BoolAnd(_to_nnf(node.left, True), _to_nnf(node.right, True))
        return BoolOr(_to_nnf(node.left, False), _to_nnf(node.right, False))
    raise TypeError(f"Unsupported BoolIR node: {type(node)!r}")


def _simplify_clause(
    raw_atoms: frozenset[ConditionAtom],
) -> tuple[frozenset[ConditionAtom] | None, bool]:
    """Simplify a single conjunction.

    Returns (simplified_clause_or_None_if_FALSE, user_exclusivity_contradiction).
    Domain invariant: a Subject has exactly one user UUID, so:
      - user(A) AND user(B) (A != B)  ==>  FALSE (contradiction)
      - user(A) AND NOT user(B) (A != B)  ==>  user(A) (redundant negative user)
    """
    # 1. Exact complementary literal check: P and (not P) ==> FALSE
    for a in raw_atoms:
        complement = ConditionAtom(a.kind, a.value, negated=not a.negated)
        if complement in raw_atoms:
            return None, False

    # 2. User UUID exclusivity domain invariant
    pos_users = [a for a in raw_atoms if a.kind is PredicateKind.USER and not a.negated]
    if len(pos_users) > 1:
        return None, True

    if len(pos_users) == 1:
        # Remove redundant `not user(other)` since `user(A)` already implies `not user(B)`
        filtered = frozenset(
            a for a in raw_atoms if not (a.kind is PredicateKind.USER and a.negated)
        )
        return filtered, False

    return raw_atoms, False


def _subsume_clauses(
    clauses: list[frozenset[ConditionAtom]],
) -> list[frozenset[ConditionAtom]]:
    """Eliminate duplicate and subsumed clauses: A or (A and B) ==> A."""
    unique = sorted(set(clauses), key=len)
    kept: list[frozenset[ConditionAtom]] = []
    for c in unique:
        if any(existing.issubset(c) for existing in kept):
            continue
        kept.append(c)
    return kept


def _minimize_dnf_clauses(
    clauses: list[frozenset[ConditionAtom]],
) -> list[frozenset[ConditionAtom]]:
    """Apply fixed-point Boolean & domain minimization on DNF clauses.

    Handles:
      1. Subsumption: A or (A and B) ==> A
      2. Unit-complement absorption: P or (not P and B) ==> P or B
      3. Complementary resolution: (C and P) or (C and not P) ==> C
      4. User-exclusivity tautology: (C and not user(A)) or (C and not user(B)) ==> C (A != B)
    """
    current = _subsume_clauses(clauses)
    while current:
        if any(len(c) == 0 for c in current):
            return [frozenset()]

        changed = False

        # 1. Unit-complement absorption: {P} absorbs `not P` from any other clause.
        unit_complements = {
            ConditionAtom(a.kind, a.value, negated=not a.negated)
            for c in current
            if len(c) == 1
            for a in c
        }
        if unit_complements:
            absorbed: list[frozenset[ConditionAtom]] = []
            for c in current:
                if len(c) > 1 and (c & unit_complements):
                    reduced = c - unit_complements
                    absorbed.append(reduced)
                    changed = True
                else:
                    absorbed.append(c)
            if changed:
                current = _subsume_clauses(absorbed)
                continue

        # 2. Complementary pair resolution: (C | {P}) or (C | {not P}) ==> C
        clause_set = set(current)
        resolved: list[frozenset[ConditionAtom]] = []
        for c in current:
            for a in c:
                if not a.negated:
                    partner = (c - {a}) | {ConditionAtom(a.kind, a.value, negated=True)}
                    if partner in clause_set:
                        resolved.append(c - {a})
                        changed = True
        if changed:
            current = _subsume_clauses(current + resolved)
            continue

        # 3. Domain invariant: a Subject has a single user UUID, so
        #    (C and not user(A)) or (C and not user(B)) (A != B) ==> C
        neg_user_contexts: dict[frozenset[ConditionAtom], set[str]] = {}
        for c in current:
            for a in c:
                if a.kind is PredicateKind.USER and a.negated:
                    ctx = c - {a}
                    neg_user_contexts.setdefault(ctx, set()).add(a.value)
        user_resolved = [
            ctx for ctx, uids in neg_user_contexts.items() if len(uids) >= 2
        ]
        if user_resolved:
            current = _subsume_clauses(current + user_resolved)
            continue

        break

    return current


def lower_to_dnf(root: BoolIR, max_clauses: int = 256) -> DNFResult:
    """Lower a BoolIR expression into canonical, minimized DNF."""
    nnf = _to_nnf(root)
    is_literal_any = isinstance(nnf, BoolConst) and nnf.value
    user_contradiction = False
    saw_non_empty_alongside_any = False

    def expand(node: BoolIR) -> list[frozenset[ConditionAtom]]:
        nonlocal user_contradiction, saw_non_empty_alongside_any
        if isinstance(node, BoolConst):
            return [frozenset()] if node.value else []
        if isinstance(node, BoolAtom):
            return [frozenset([node.atom])]
        if isinstance(node, BoolOr):
            left = expand(node.left)
            right = expand(node.right)
            combined = left + right
            has_empty = any(len(c) == 0 for c in combined)
            has_non_empty = any(len(c) > 0 for c in combined)
            if has_empty and has_non_empty:
                saw_non_empty_alongside_any = True
            reduced = _minimize_dnf_clauses(combined)
            if len(reduced) > max_clauses:
                raise DNFComplexityError(
                    f"DNF expansion exceeded safety limit of {max_clauses} clauses."
                )
            return reduced
        if isinstance(node, BoolAnd):
            left = expand(node.left)
            right = expand(node.right)
            if not left or not right:
                return []
            product: list[frozenset[ConditionAtom]] = []
            for lc in left:
                for rc in right:
                    merged, had_u_contra = _simplify_clause(lc | rc)
                    if had_u_contra:
                        user_contradiction = True
                    if merged is not None:
                        product.append(merged)
                    if len(product) > max_clauses * 4:
                        product = _minimize_dnf_clauses(product)
                        if len(product) > max_clauses:
                            raise DNFComplexityError(
                                f"DNF expansion exceeded safety limit of {max_clauses} clauses."
                            )
            reduced = _minimize_dnf_clauses(product)
            if len(reduced) > max_clauses:
                raise DNFComplexityError(
                    f"DNF expansion exceeded safety limit of {max_clauses} clauses."
                )
            return reduced
        raise TypeError(f"Unexpected NNF node: {type(node)!r}")

    raw_clauses = _minimize_dnf_clauses(expand(nnf))
    sorted_clauses = tuple(
        DNFClause(atoms=tuple(sorted(c, key=lambda a: a.sort_key())))
        for c in sorted(
            raw_clauses,
            key=lambda c: tuple(
                a.sort_key() for a in sorted(c, key=lambda a: a.sort_key())
            ),
        )
    )
    simplified_to_tautology = (
        len(sorted_clauses) == 1
        and sorted_clauses[0].is_tautology
        and not is_literal_any
        and not saw_non_empty_alongside_any
    )
    return DNFResult(
        clauses=sorted_clauses,
        had_user_exclusivity_contradiction=user_contradiction,
        was_absorbed_by_any=saw_non_empty_alongside_any,
        simplified_to_tautology=simplified_to_tautology,
    )
