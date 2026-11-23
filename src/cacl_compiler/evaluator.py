from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from .ast_nodes import Effect, PredicateKind, Scope
from .ir import CompiledPolicy, CompiledRule, ConditionAtom, DNFClause
from .permissions import (
    AtomicOp,
    ObjectState,
    ObjectType,
    op_applies_to_object,
    op_applies_to_state,
)


@dataclass(frozen=True, slots=True)
class Subject:
    """Authenticated security principal; authorization ALWAYS binds to immutable user_id (UUID)."""

    user_id: UUID
    username: str | None = None
    groups: frozenset[str] = frozenset()
    perms: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class NamespaceNode:
    node_id: str
    name: str
    object_type: ObjectType
    state: ObjectState
    policy: CompiledPolicy


@dataclass(frozen=True, slots=True)
class MatchedRuleTrace:
    node_id: str
    node_name: str
    distance: int
    rule_index: int
    effect: Effect
    scope: Scope
    remark: str | None


@dataclass(frozen=True, slots=True)
class EvalDecision:
    allowed: bool
    reason: str
    step: str
    matched_denies: tuple[MatchedRuleTrace, ...] = ()
    matched_allows: tuple[MatchedRuleTrace, ...] = ()
    effective_allow_mask: int = 0
    effective_deny_mask: int = 0


# Mandatory redline callback: return denial reason string to block immediately, or None to pass.
RedlineHook = Callable[[Subject, NamespaceNode, AtomicOp], str | None]


def scope_matches(scope: Scope, distance: int, target_type: ObjectType) -> bool:
    """CEP-0002 Section 4 Scope Matching Matrix."""
    if scope is Scope.SELF:
        return distance == 0
    if scope is Scope.DIRS:
        return target_type is ObjectType.DIRECTORY
    if scope is Scope.DOCS:
        return target_type is ObjectType.DOCUMENT
    return True  # Scope.ALL


def rule_active_at(rule: CompiledRule, eval_time_utc: datetime) -> bool:
    """Half-open interval check: valid_from <= t < valid_until."""
    if rule.valid_from is not None and eval_time_utc < rule.valid_from:
        return False
    return not (rule.valid_until is not None and eval_time_utc >= rule.valid_until)


def _eval_atom(atom: ConditionAtom, subject: Subject) -> bool:
    if atom.kind is PredicateKind.USER:
        matched = atom.value.lower() == str(subject.user_id).lower()
    elif atom.kind is PredicateKind.GROUP:
        matched = atom.value in subject.groups
    elif atom.kind is PredicateKind.PERM:
        matched = atom.value in subject.perms
    elif atom.kind is PredicateKind.ROLE:
        matched = atom.value in subject.roles
    else:
        matched = False
    return (not matched) if atom.negated else matched


def eval_dnf(clauses: tuple[DNFClause, ...], subject: Subject) -> bool:
    for clause in clauses:
        if all(_eval_atom(atom, subject) for atom in clause.atoms):
            return True
    return False


def _evaluate_dacl_on_chain(
    subject: Subject,
    chain_root_to_target: list[NamespaceNode],
    op: AtomicOp,
    eval_time_utc: datetime,
) -> tuple[bool, list[MatchedRuleTrace], list[MatchedRuleTrace], int, int]:
    """Steps 4 & 5: Assemble inherited DACLs (respecting `inherit off`) and apply deny-overrides."""
    target = chain_root_to_target[-1]
    effective_nodes: list[tuple[int, NamespaceNode]] = []
    # Walk upward from target (distance 0) to root, stopping when a node sets inherit=False
    for dist, node in enumerate(reversed(chain_root_to_target)):
        effective_nodes.append((dist, node))
        if not node.policy.inherit:
            break

    matched_denies: list[MatchedRuleTrace] = []
    matched_allows: list[MatchedRuleTrace] = []
    allow_mask = 0
    deny_mask = 0

    for dist, node in effective_nodes:
        for idx, rule in enumerate(node.policy.rules):
            if not scope_matches(rule.scope, dist, target.object_type):
                continue
            if not rule_active_at(rule, eval_time_utc):
                continue
            if not eval_dnf(rule.dnf_clauses, subject):
                continue

            if rule.effect is Effect.DENY:
                deny_mask |= rule.permission_mask
                if rule.permission_mask & int(op):
                    matched_denies.append(
                        MatchedRuleTrace(
                            node.node_id,
                            node.name,
                            dist,
                            idx,
                            Effect.DENY,
                            rule.scope,
                            rule.remark,
                        )
                    )
            else:
                allow_mask |= rule.permission_mask
                if rule.permission_mask & int(op):
                    matched_allows.append(
                        MatchedRuleTrace(
                            node.node_id,
                            node.name,
                            dist,
                            idx,
                            Effect.ALLOW,
                            rule.scope,
                            rule.remark,
                        )
                    )

    if matched_denies:
        return False, matched_denies, matched_allows, allow_mask, deny_mask
    if matched_allows:
        return True, matched_denies, matched_allows, allow_mask, deny_mask
    return False, matched_denies, matched_allows, allow_mask, deny_mask


def evaluate_access(
    subject: Subject,
    path_root_to_target: list[NamespaceNode],
    operation: AtomicOp,
    eval_time_utc: datetime | None = None,
    redlines: list[RedlineHook] | None = None,
    check_ancestor_traverse: bool = True,
) -> EvalDecision:
    """CEP-0002 Section 6 deterministic runtime evaluation pipeline."""
    if not path_root_to_target:
        raise ValueError("path_root_to_target must contain at least the target node.")

    now = (eval_time_utc or datetime.now(UTC)).astimezone(UTC)
    target = path_root_to_target[-1]

    # Step 1: Object type & lifecycle state applicability
    if not op_applies_to_object(operation, target.object_type):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable to {target.object_type.value}.",
            step="1_lifecycle_and_type",
        )
    if not op_applies_to_state(operation, target.state):
        return EvalDecision(
            allowed=False,
            reason=f"Operation {operation.name} is not applicable in state {target.state.value}.",
            step="1_lifecycle_and_type",
        )

    # Step 2: Ancestor directory TRAVERSE checks
    if check_ancestor_traverse and len(path_root_to_target) > 1:
        for idx in range(len(path_root_to_target) - 1):
            ancestor = path_root_to_target[idx]
            if ancestor.state is not ObjectState.NORMAL:
                return EvalDecision(
                    allowed=False,
                    reason=f"Ancestor '{ancestor.name}' ({ancestor.node_id}) is not in normal state.",
                    step="2_path_traverse",
                )
            ok, denies, allows, a_mask, d_mask = _evaluate_dacl_on_chain(
                subject, path_root_to_target[: idx + 1], AtomicOp.TRAVERSE, now
            )
            if not ok:
                return EvalDecision(
                    allowed=False,
                    reason=f"Missing TRAVERSE permission on ancestor '{ancestor.name}' ({ancestor.node_id}).",
                    step="2_path_traverse",
                    matched_denies=tuple(denies),
                    matched_allows=tuple(allows),
                    effective_allow_mask=a_mask,
                    effective_deny_mask=d_mask,
                )

    # Step 3: Mandatory system redlines
    for hook in redlines or []:
        block_reason = hook(subject, target, operation)
        if block_reason is not None:
            return EvalDecision(
                allowed=False,
                reason=f"Blocked by mandatory redline: {block_reason}",
                step="3_mandatory_redline",
            )

    # Steps 4 & 5: DACL assembly + Deny-Overrides + Default-Deny
    _allowed, denies, allows, a_mask, d_mask = _evaluate_dacl_on_chain(
        subject, path_root_to_target, operation, now
    )
    if denies:
        return EvalDecision(
            allowed=False,
            reason=f"Explicitly denied by {len(denies)} matching deny rule(s).",
            step="5_deny_overrides",
            matched_denies=tuple(denies),
            matched_allows=tuple(allows),
            effective_allow_mask=a_mask,
            effective_deny_mask=d_mask,
        )
    if allows:
        return EvalDecision(
            allowed=True,
            reason=f"Allowed by {len(allows)} matching allow rule(s) with no overriding deny.",
            step="5_allow_matched",
            matched_allows=tuple(allows),
            effective_allow_mask=a_mask,
            effective_deny_mask=d_mask,
        )
    return EvalDecision(
        allowed=False,
        reason="Default-deny: no matching allow rule granted the requested operation.",
        step="5_default_deny",
        effective_allow_mask=a_mask,
        effective_deny_mask=d_mask,
    )


def evaluate_reparent(
    subject: Subject,
    source_path: list[NamespaceNode],
    dest_parent_path: list[NamespaceNode],
    eval_time_utc: datetime | None = None,
    redlines: list[RedlineHook] | None = None,
) -> EvalDecision:
    """Step 6 example: cross-object composite authorization for reparenting an object."""
    src_decision = evaluate_access(
        subject, source_path, AtomicOp.REPARENT, eval_time_utc, redlines
    )
    if not src_decision.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"Source check failed: {src_decision.reason}",
            step="6_composite_source",
            matched_denies=src_decision.matched_denies,
            matched_allows=src_decision.matched_allows,
        )

    src_node = source_path[-1]
    dest_op = (
        AtomicOp.CREATE_DOCUMENT
        if src_node.object_type is ObjectType.DOCUMENT
        else AtomicOp.CREATE_DIRECTORY
    )
    dst_decision = evaluate_access(
        subject, dest_parent_path, dest_op, eval_time_utc, redlines
    )
    if not dst_decision.allowed:
        return EvalDecision(
            allowed=False,
            reason=f"Destination check ({dest_op.name}) failed: {dst_decision.reason}",
            step="6_composite_destination",
            matched_denies=dst_decision.matched_denies,
            matched_allows=dst_decision.matched_allows,
        )
    return EvalDecision(
        allowed=True,
        reason=f"Composite reparent authorized (REPARENT on source + {dest_op.name} on destination).",
        step="6_composite_allowed",
    )


@dataclass(frozen=True, slots=True)
class SaveAuthzResult:
    authorized: bool
    reason: str
    self_lockout_warning: bool = False


def authorize_policy_save(
    actor: Subject,
    current_path: list[NamespaceNode],
    proposed_policy: CompiledPolicy,
    eval_time_utc: datetime | None = None,
    redlines: list[RedlineHook] | None = None,
) -> SaveAuthzResult:
    """CEP-0002 Section 5.2 Save-time authorization (WRITE_DACL + anti-lockout advisory)."""
    check = evaluate_access(
        actor, current_path, AtomicOp.WRITE_DACL, eval_time_utc, redlines
    )
    if not check.allowed:
        return SaveAuthzResult(
            authorized=False, reason=f"Missing WRITE_DACL: {check.reason}"
        )

    # Simulate whether the actor would retain WRITE_DACL after saving the proposed policy
    target = current_path[-1]
    simulated_target = NamespaceNode(
        node_id=target.node_id,
        name=target.name,
        object_type=target.object_type,
        state=target.state,
        policy=proposed_policy,
    )
    post_check = evaluate_access(
        actor,
        current_path[:-1] + [simulated_target],
        AtomicOp.WRITE_DACL,
        eval_time_utc,
        redlines,
    )
    return SaveAuthzResult(
        authorized=True,
        reason="Actor holds WRITE_DACL.",
        self_lockout_warning=not post_check.allowed,
    )
