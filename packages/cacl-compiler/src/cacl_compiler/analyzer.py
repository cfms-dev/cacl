import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .ast_nodes import (
    AnyExprNode,
    BinaryExprNode,
    Effect,
    ExprNode,
    NotExprNode,
    PolicyAST,
    PredicateExprNode,
    PredicateKind,
    RuleNode,
    Scope,
)
from .diagnostics import Diagnostic, Severity, Span
from .dnf import (
    BoolAnd,
    BoolAtom,
    BoolConst,
    BoolIR,
    BoolNot,
    BoolOr,
    DNFComplexityError,
    lower_to_dnf,
)
from .identity import PrincipalResolver, parse_canonical_uuid
from .ir import CompiledPolicy, CompiledRule, ConditionAtom
from .parser import parse_cacl
from .permissions import (
    ATOMIC_OP_BY_NAME,
    DEFAULT_PRESET_MACROS,
    DIR_APPLICABLE_MASK,
    DIR_ONLY_MASK,
    DOC_APPLICABLE_MASK,
    DOC_ONLY_MASK,
    ObjectType,
    mask_to_atomic_names,
)

_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})\Z"
)


@dataclass(slots=True)
class CompilerConfig:
    """Configuration knobs for standalone compilation."""

    resolver: PrincipalResolver | None = None
    # When True and resolver is present, unknown principals are errors; False emits warnings.
    strict_principal_existence: bool = True
    # Optional target object type context (DIRECTORY or DOCUMENT) for deeper scope diagnostics.
    target_object_type: ObjectType | None = None
    # Reference UTC clock for expired-rule warnings (defaults to current UTC time).
    now_utc: datetime | None = None
    # Custom macro table override (defaults to CEP 2 presets).
    macros: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_PRESET_MACROS))
    # Guard against exponential DNF blowup.
    max_dnf_clauses: int = 256


@dataclass(slots=True)
class CompileResult:
    policy: CompiledPolicy | None
    diagnostics: list[Diagnostic]

    @property
    def ok(self) -> bool:
        return self.policy is not None and not any(
            d.severity is Severity.ERROR for d in self.diagnostics
        )

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity is Severity.WARNING]


def _parse_rfc3339_utc(raw: str) -> datetime | None:
    if not _RFC3339_RE.match(raw):
        return None
    normalized = raw.replace("t", "T").replace("z", "Z")
    # Truncate sub-microsecond nanoseconds (Python datetime precision is microseconds)
    if "." in normalized:
        head, tail = normalized.split(".", 1)
        tz_idx = next((i for i, ch in enumerate(tail) if ch in "Z+-"), len(tail))
        frac = tail[:tz_idx][:6]
        tz = tail[tz_idx:]
        normalized = f"{head}.{frac}{tz}"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(UTC)


def compile_ast(ast: PolicyAST, config: CompilerConfig | None = None) -> CompileResult:
    cfg = config or CompilerConfig()
    diags: list[Diagnostic] = []
    now_utc = (cfg.now_utc or datetime.now(UTC)).astimezone(UTC)

    # 1. Directive uniqueness check
    inherit_enabled = True
    if len(ast.directives) > 1:
        for dup in ast.directives[1:]:
            diags.append(
                Diagnostic(
                    code="E201",
                    severity=Severity.ERROR,
                    message="Duplicate 'inherit' directive; at most one is permitted per policy.",
                    span=dup.span,
                )
            )
    if ast.directives:
        inherit_enabled = ast.directives[0].enabled

    # Helper: resolve predicate node into BoolIR
    def resolve_expr(node: ExprNode) -> BoolIR:
        if isinstance(node, AnyExprNode):
            return BoolConst(True)
        if isinstance(node, NotExprNode):
            return BoolNot(resolve_expr(node.operand))
        if isinstance(node, BinaryExprNode):
            left = resolve_expr(node.left)
            right = resolve_expr(node.right)
            return BoolAnd(left, right) if node.op == "and" else BoolOr(left, right)
        if isinstance(node, PredicateExprNode):
            return resolve_predicate(node)
        raise TypeError(f"Unknown AST expr node: {type(node)!r}")

    def resolve_predicate(node: PredicateExprNode) -> BoolIR:
        kind = node.kind
        raw = node.raw_value

        if not raw:
            diags.append(
                Diagnostic(
                    code="E204",
                    severity=Severity.ERROR,
                    message=f"Predicate '{kind.value}(...)' cannot have an empty identifier.",
                    span=node.span,
                )
            )
            return BoolAtom(ConditionAtom(kind, raw))

        # CEP 2 §4 & §5.1(5): user("id") must strictly conform to 36-char RFC 9562 UUID.
        if kind is PredicateKind.USER:
            parsed_uuid = parse_canonical_uuid(raw)
            if parsed_uuid is None:
                diags.append(
                    Diagnostic(
                        code="E302",
                        severity=Severity.ERROR,
                        message=(
                            f"User identifier '{raw}' is not a valid 36-character hyphenated RFC 9562 UUID."
                        ),
                        span=node.span,
                        hint=(
                            "Use a canonical 8-4-4-4-12 hexadecimal UUID; mutable usernames "
                            "are prohibited in CACL syntax."
                        ),
                    )
                )
                return BoolAtom(ConditionAtom(kind, raw))

            canonical_id = str(parsed_uuid)
            if cfg.resolver is not None and not cfg.resolver.user_exists(parsed_uuid):
                sev = (
                    Severity.ERROR
                    if cfg.strict_principal_existence
                    else Severity.WARNING
                )
                diags.append(
                    Diagnostic(
                        code="E301" if sev is Severity.ERROR else "W301",
                        severity=sev,
                        message=f"User UUID '{canonical_id}' does not exist in principal directory.",
                        span=node.span,
                    )
                )
            return BoolAtom(ConditionAtom(kind, canonical_id))

        # --- GROUP & PERM existence checks (if resolver supports them) ---
        if kind is PredicateKind.GROUP and cfg.resolver is not None:
            exists = cfg.resolver.group_exists(raw)
            if exists is False:
                sev = (
                    Severity.ERROR
                    if cfg.strict_principal_existence
                    else Severity.WARNING
                )
                diags.append(
                    Diagnostic(
                        code="E303" if sev is Severity.ERROR else "W304",
                        severity=sev,
                        message=f"Group '{raw}' does not exist in principal directory.",
                        span=node.span,
                    )
                )
        elif kind is PredicateKind.PERM and cfg.resolver is not None:
            exists = cfg.resolver.perm_exists(raw)
            if exists is False:
                sev = (
                    Severity.ERROR
                    if cfg.strict_principal_existence
                    else Severity.WARNING
                )
                diags.append(
                    Diagnostic(
                        code="E304" if sev is Severity.ERROR else "W305",
                        severity=sev,
                        message=f"System capability '{raw}' is not registered.",
                        span=node.span,
                    )
                )

        return BoolAtom(ConditionAtom(kind, raw))

    # 2. Validate & compile each rule
    compiled_rules: list[CompiledRule] = []
    rule_spans: list[Span] = []

    for rule in ast.rules:
        compiled = _compile_single_rule(rule, cfg, now_utc, resolve_expr, diags)
        if compiled is not None:
            compiled_rules.append(compiled)
            rule_spans.append(rule.span)

    # 3. Cross-rule static analysis (duplicates & unconditional deny shadowing)
    seen_rules: dict[tuple, int] = {}
    for idx, cr in enumerate(compiled_rules):
        key = cr.semantic_key()
        if key in seen_rules:
            diags.append(
                Diagnostic(
                    code="W211",
                    severity=Severity.WARNING,
                    message=f"Rule is semantically identical to rule #{seen_rules[key] + 1}.",
                    span=rule_spans[idx],
                )
            )
        else:
            seen_rules[key] = idx

    # Detect allow rules completely shadowed by an unconditional permanent `deny ... on all to any`
    global_deny_mask = 0
    for cr in compiled_rules:
        if (
            cr.effect is Effect.DENY
            and cr.scope is Scope.ALL
            and cr.is_unconditional
            and cr.valid_from is None
            and cr.valid_until is None
        ):
            global_deny_mask |= cr.permission_mask

    if global_deny_mask:
        for idx, cr in enumerate(compiled_rules):
            if cr.effect is Effect.ALLOW and (cr.permission_mask & global_deny_mask):
                shadowed = mask_to_atomic_names(cr.permission_mask & global_deny_mask)
                diags.append(
                    Diagnostic(
                        code="W212",
                        severity=Severity.WARNING,
                        message=(
                            f"Allow rule permissions {shadowed} are permanently overridden by "
                            "an unconditional 'deny ... on all to any' rule in the same policy."
                        ),
                        span=rule_spans[idx],
                    )
                )

    has_errors = any(d.severity is Severity.ERROR for d in diags)
    policy = (
        None
        if has_errors
        else CompiledPolicy(
            inherit=inherit_enabled,
            rules=tuple(compiled_rules),
        )
    )
    return CompileResult(policy=policy, diagnostics=diags)


def _compile_single_rule(
    rule: RuleNode,
    cfg: CompilerConfig,
    now_utc: datetime,
    resolve_expr,
    diags: list[Diagnostic],
) -> CompiledRule | None:
    # A. Operation set algebra & macro expansion
    mask = 0
    for idx, item in enumerate(rule.op_items):
        op_meta = ATOMIC_OP_BY_NAME.get(item.name)
        if op_meta is not None:
            item_mask = int(op_meta.op)
        elif item.name in cfg.macros:
            item_mask = cfg.macros[item.name]
        else:
            diags.append(
                Diagnostic(
                    code="E202",
                    severity=Severity.ERROR,
                    message=f"Unknown atomic operation or permission macro '{item.name}'.",
                    span=item.span,
                )
            )
            continue

        if item.subtract:
            if idx == 0:
                diags.append(
                    Diagnostic(
                        code="E210",
                        severity=Severity.ERROR,
                        message=f"The leading operation item must not be negative ('-{item.name}').",
                        span=item.span,
                        hint="Start the operation set with an unsigned operation or macro.",
                    )
                )
                continue
            if (mask & item_mask) != item_mask:
                missing = mask_to_atomic_names(item_mask & ~mask)
                diags.append(
                    Diagnostic(
                        code="W201",
                        severity=Severity.WARNING,
                        message=(
                            f"Subtracting '-{item.name}' removes bits that are not currently "
                            f"present: {missing}."
                        ),
                        span=item.span,
                    )
                )
            mask &= ~item_mask
        else:
            if (mask & item_mask) == item_mask:
                diags.append(
                    Diagnostic(
                        code="W202",
                        severity=Severity.WARNING,
                        message=f"Adding '{item.name}' is redundant; all of its bits are already present.",
                        span=item.span,
                    )
                )
            mask |= item_mask

    if mask == 0:
        diags.append(
            Diagnostic(
                code="E203",
                severity=Severity.ERROR,
                message="Operation set evaluates to an empty bitmask (0x000000).",
                span=rule.op_set_span,
                hint="A rule must grant or deny at least one effective atomic operation.",
            )
        )

    # B. Scope vs. Operation compatibility diagnostics
    _check_scope_compatibility(rule, mask, cfg.target_object_type, diags)

    # C. Match clause (`to` vs `when`) validation & DNF lowering
    if rule.match.syntax == "to":
        seen_to: set[tuple[str, str]] = set()
        for item in rule.match.to_items:
            if isinstance(item, PredicateExprNode):
                if item.kind is PredicateKind.PERM:
                    diags.append(
                        Diagnostic(
                            code="E205",
                            severity=Severity.ERROR,
                            message="Capability predicate 'perm(...)' is only allowed in 'when' clauses, not 'to'.",
                            span=item.span,
                            hint=f'Use: when perm("{item.raw_value}")',
                        )
                    )
                norm_val = (
                    item.raw_value.lower()
                    if item.kind is PredicateKind.USER
                    else item.raw_value
                )
                key = (item.kind.value, norm_val)
                if key in seen_to:
                    diags.append(
                        Diagnostic(
                            code="W208",
                            severity=Severity.WARNING,
                            message=f"Duplicate principal '{item.kind.value}(\"{item.raw_value}\")' in 'to' list.",
                            span=item.span,
                        )
                    )
                seen_to.add(key)

    bool_ir = resolve_expr(rule.match.expr)
    try:
        dnf_res = lower_to_dnf(bool_ir, max_clauses=cfg.max_dnf_clauses)
    except DNFComplexityError as exc:
        diags.append(
            Diagnostic(
                code="E208",
                severity=Severity.ERROR,
                message=str(exc),
                span=rule.match.span or rule.span,
                hint="Simplify deeply nested boolean expressions or split into multiple rules.",
            )
        )
        return None

    if len(dnf_res.clauses) == 0:
        reason = (
            "a single subject cannot simultaneously hold two distinct user UUIDs"
            if dnf_res.had_user_exclusivity_contradiction
            else "the boolean condition is a logical contradiction (always FALSE)"
        )
        diags.append(
            Diagnostic(
                code="W206",
                severity=Severity.WARNING,
                message=f"Dead rule: condition is unsatisfiable ({reason}).",
                span=rule.match.span or rule.span,
            )
        )
    elif dnf_res.was_absorbed_by_any:
        diags.append(
            Diagnostic(
                code="W207",
                severity=Severity.WARNING,
                message="Condition contains 'any' in a disjunction; other branches are trivially absorbed.",
                span=rule.match.span or rule.span,
            )
        )

    # D. Temporal window validation (RFC 3339 + [valid_from, valid_until))
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    if rule.time_window is not None:
        tw = rule.time_window
        if tw.valid_from is not None:
            valid_from = _parse_rfc3339_utc(tw.valid_from)
            if valid_from is None:
                diags.append(
                    Diagnostic(
                        code="E206",
                        severity=Severity.ERROR,
                        message=f"Invalid RFC 3339 timestamp in 'from': '{tw.valid_from}'.",
                        span=tw.from_span,
                        hint='Include an explicit timezone offset, e.g. "2026-11-23T00:00:00Z".',
                    )
                )
        if tw.valid_until is not None:
            valid_until = _parse_rfc3339_utc(tw.valid_until)
            if valid_until is None:
                diags.append(
                    Diagnostic(
                        code="E206",
                        severity=Severity.ERROR,
                        message=f"Invalid RFC 3339 timestamp in 'until': '{tw.valid_until}'.",
                        span=tw.until_span,
                        hint='Include an explicit timezone offset, e.g. "2026-12-31T23:59:59Z".',
                    )
                )
        if (
            valid_from is not None
            and valid_until is not None
            and valid_from >= valid_until
        ):
            diags.append(
                Diagnostic(
                    code="E207",
                    severity=Severity.ERROR,
                    message=(
                        "Inverted or empty time window: 'from' must be strictly earlier than 'until' "
                        "(half-open interval [from, until))."
                    ),
                    span=tw.span,
                )
            )
        if valid_until is not None and valid_until <= now_utc:
            diags.append(
                Diagnostic(
                    code="W209",
                    severity=Severity.WARNING,
                    message="Rule has already expired relative to compile-time UTC clock.",
                    span=tw.until_span or tw.span,
                )
            )
        if rule.effect is Effect.DENY and valid_until is not None:
            diags.append(
                Diagnostic(
                    code="W210",
                    severity=Severity.WARNING,
                    message=(
                        "Temporary 'deny' rule with 'until': once expired, inherited or peer 'allow' "
                        "rules will automatically resume granting access."
                    ),
                    span=tw.until_span or tw.span,
                )
            )

    return CompiledRule(
        effect=rule.effect,
        permission_mask=mask,
        scope=rule.scope,
        dnf_clauses=dnf_res.clauses,
        valid_from=valid_from,
        valid_until=valid_until,
        remark=rule.remark,
    )


def _check_scope_compatibility(
    rule: RuleNode,
    mask: int,
    target_type: ObjectType | None,
    diags: list[Diagnostic],
) -> None:
    # CEP 2 5.1: warn when the scope can never intersect any applicable operation.
    if mask != 0:
        if rule.scope is Scope.DIRS and not (mask & DIR_APPLICABLE_MASK):
            diags.append(
                Diagnostic(
                    code="W204",
                    severity=Severity.WARNING,
                    message="Scope 'on dirs' has no effect: no operation in the set applies to directories.",
                    span=rule.scope_span or rule.op_set_span,
                )
            )
        elif rule.scope is Scope.DOCS and not (mask & DOC_APPLICABLE_MASK):
            diags.append(
                Diagnostic(
                    code="W203",
                    severity=Severity.WARNING,
                    message="Scope 'on docs' has no effect: no operation in the set applies to documents.",
                    span=rule.scope_span or rule.op_set_span,
                )
            )

    if target_type is ObjectType.DOCUMENT:
        if rule.scope is Scope.DIRS:
            diags.append(
                Diagnostic(
                    code="W205",
                    severity=Severity.WARNING,
                    message="Scope 'on dirs' attached to a document matches nothing.",
                    span=rule.scope_span or rule.span,
                )
            )
        elif rule.scope is Scope.SELF and (mask & DIR_ONLY_MASK):
            diags.append(
                Diagnostic(
                    code="W205",
                    severity=Severity.WARNING,
                    message=(
                        f"Directory-only operations {mask_to_atomic_names(mask & DIR_ONLY_MASK)} "
                        "have no effect on a document with 'on self'."
                    ),
                    span=rule.op_set_span,
                )
            )
    elif (
        target_type is ObjectType.DIRECTORY
        and rule.scope is Scope.SELF
        and (mask & DOC_ONLY_MASK)
    ):
        diags.append(
            Diagnostic(
                code="W205",
                severity=Severity.WARNING,
                message=(
                    f"Document-only operations {mask_to_atomic_names(mask & DOC_ONLY_MASK)} "
                    "have no effect on a directory with 'on self'."
                ),
                span=rule.op_set_span,
            )
        )


def compile_cacl(source: str, config: CompilerConfig | None = None) -> CompileResult:
    """End-to-end entry point: CACL source text -> CompiledPolicy + Diagnostics."""
    ast, parse_diags = parse_cacl(source)
    if ast is None or any(d.severity is Severity.ERROR for d in parse_diags):
        return CompileResult(policy=None, diagnostics=parse_diags)

    res = compile_ast(ast, config=config)
    return CompileResult(policy=res.policy, diagnostics=parse_diags + res.diagnostics)
