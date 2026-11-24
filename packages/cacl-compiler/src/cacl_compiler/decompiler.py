from collections.abc import Mapping
from dataclasses import dataclass

from .analyzer import CompilerConfig, compile_cacl
from .ast_nodes import PredicateKind, Scope
from .ir import (
    CompiledPolicy,
    CompiledRule,
    ConditionAtom,
    DNFClause,
    format_utc_rfc3339,
)
from .permissions import mask_to_atomic_names, mask_to_folded_tokens


@dataclass(slots=True)
class DecompileOptions:
    # Optional canonical lowercase user UUID -> label mapping for transient `# @label` comments.
    user_annotations: Mapping[str, str] | None = None
    fold_presets: bool = False  # False = pure atomic ops; True = greedy macro folding
    prefer_to_syntax: bool = (
        True  # Render positive principal-only OR chains as `to ...`
    )
    # CEP 2 canonical form omits the default `on all`; set False to emit it explicitly.
    omit_default_scope: bool = True
    always_emit_inherit: bool = True


def escape_cacl_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _render_atom(
    atom: ConditionAtom,
    opts: DecompileOptions,
    annotations: list[str],
) -> str:
    if atom.kind is PredicateKind.USER and opts.user_annotations is not None:
        label = opts.user_annotations.get(atom.value)
        if label is not None:
            annotations.append(f"@{label}")

    base = f"{atom.kind.value}({escape_cacl_string(atom.value)})"
    return f"not {base}" if atom.negated else base


def _can_render_as_to(clauses: tuple[DNFClause, ...]) -> bool:
    """True iff DNF is `any` or a pure positive disjunction of single non-perm principals."""
    if len(clauses) == 1 and clauses[0].is_tautology:
        return True
    if not clauses:
        return False
    for clause in clauses:
        if len(clause.atoms) != 1:
            return False
        atom = clause.atoms[0]
        if atom.negated or atom.kind is PredicateKind.PERM:
            return False
    return True


def _render_condition(
    rule: CompiledRule,
    opts: DecompileOptions,
    annotations: list[str],
) -> str:
    if rule.is_unsatisfiable:
        # Canonical lossless encoding of FALSE in CACL syntax
        return "when not any"

    if rule.is_unconditional:
        return "to any" if opts.prefer_to_syntax else "when any"

    if opts.prefer_to_syntax and _can_render_as_to(rule.dnf_clauses):
        items = [_render_atom(c.atoms[0], opts, annotations) for c in rule.dnf_clauses]
        return "to " + ", ".join(items)

    # Render DNF: `and` binds tighter than `or`, so no parentheses are needed around conjunctions
    clause_strs: list[str] = []
    for clause in rule.dnf_clauses:
        if clause.is_tautology:
            clause_strs.append("any")
        else:
            clause_strs.append(
                " and ".join(_render_atom(a, opts, annotations) for a in clause.atoms)
            )
    return "when " + " or ".join(clause_strs)


def decompile_rule(rule: CompiledRule, opts: DecompileOptions | None = None) -> str:
    options = opts or DecompileOptions()
    op_names = (
        mask_to_folded_tokens(rule.permission_mask)
        if options.fold_presets
        else mask_to_atomic_names(rule.permission_mask)
    )
    parts: list[str] = [rule.effect.value, f"[{', '.join(op_names)}]"]

    if not (options.omit_default_scope and rule.scope is Scope.ALL):
        parts.append(f"on {rule.scope.value}")

    annotations: list[str] = []
    parts.append(_render_condition(rule, options, annotations))

    if rule.valid_from is not None:
        parts.append(f"from {escape_cacl_string(format_utc_rfc3339(rule.valid_from))}")
    if rule.valid_until is not None:
        parts.append(
            f"until {escape_cacl_string(format_utc_rfc3339(rule.valid_until))}"
        )
    if rule.remark is not None:
        parts.append(f"remark {escape_cacl_string(rule.remark)}")

    stmt = " ".join(parts) + ";"
    if annotations:
        stmt += f"  # {', '.join(dict.fromkeys(annotations))}"
    return stmt


def decompile_policy(
    policy: CompiledPolicy, opts: DecompileOptions | None = None
) -> str:
    """Semantically lossless decompilation from CompiledPolicy back into canonical CACL text."""
    options = opts or DecompileOptions()
    lines: list[str] = []
    if options.always_emit_inherit or not policy.inherit:
        lines.append(f"inherit {'on' if policy.inherit else 'off'};")
    if lines and policy.rules:
        lines.append("")
    for rule in policy.rules:
        lines.append(decompile_rule(rule, options))
    return "\n".join(lines) + ("\n" if lines else "")


def format_cacl(
    source: str,
    compile_config: CompilerConfig | None = None,
    decompile_options: DecompileOptions | None = None,
) -> tuple[str | None, list]:
    """Compile and decompile back into canonical formatted CACL source."""
    res = compile_cacl(source, config=compile_config)
    if not res.ok or res.policy is None:
        return None, res.diagnostics
    return decompile_policy(res.policy, opts=decompile_options), res.diagnostics
