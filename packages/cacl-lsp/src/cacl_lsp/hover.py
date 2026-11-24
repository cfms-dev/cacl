from cacl_compiler import (
    ATOMIC_OP_BY_NAME,
    DEFAULT_PRESET_MACROS,
    parse_canonical_uuid,
)
from cacl_compiler.analyzer import _parse_rfc3339_utc
from cacl_compiler.ast_nodes import RuleNode
from cacl_compiler.ir import CompiledRule, format_utc_rfc3339
from cacl_compiler.permissions import mask_to_atomic_names
from lsprotocol import types

from .analysis import DocumentState, evaluate_rule_op_mask
from .docs import (
    SCOPE_DESCRIPTIONS,
    format_atomic_op_markdown,
    format_keyword_markdown,
    format_macro_markdown,
    format_predicate_markdown,
    format_scope_markdown,
)
from .lexer import LexToken, TokenKind, token_at_offset


def _hover(markdown: str, state: DocumentState, tok: LexToken) -> types.Hover:
    return types.Hover(
        contents=types.MarkupContent(
            kind=types.MarkupKind.Markdown,
            value=markdown,
        ),
        range=state.line_index.span_to_range(tok.span),
    )


def _find_rule_at_position(
    state: DocumentState,
    position: types.Position,
) -> tuple[int, RuleNode] | None:
    if state.ast is None:
        return None
    for idx, rule in enumerate(state.ast.rules):
        if state.line_index.contains_position(rule.span, position):
            return idx, rule
    return None


def _compiled_rule_at(state: DocumentState, rule_idx: int) -> CompiledRule | None:
    if (
        state.compile_result is not None
        and state.compile_result.policy is not None
        and 0 <= rule_idx < len(state.compile_result.policy.rules)
    ):
        return state.compile_result.policy.rules[rule_idx]
    return None


def _format_rule_summary(
    rule: RuleNode,
    compiled: CompiledRule | None,
) -> str:
    mask, all_valid = evaluate_rule_op_mask(rule)
    lines = ["---", "**Rule Summary**"]
    if all_valid and mask > 0:
        ops = mask_to_atomic_names(mask)
        lines.append(f"- **Effective Mask**: `0x{mask:06x}` ({len(ops)} atomic ops)")
        lines.append("- **Operations**: " + ", ".join(f"`{op}`" for op in ops))
    elif mask == 0:
        lines.append("- **Effective Mask**: `0x000000` (empty)")
    else:
        lines.append("- **Effective Mask**: contains unknown or invalid operation items")

    scope_note = "" if rule.scope_explicit else " *(implicit default)*"
    lines.append(f"- **Scope**: `on {rule.scope.value}`{scope_note}")

    if compiled is not None:
        if compiled.is_unsatisfiable:
            lines.append("- **Condition**: Unsatisfiable (`FALSE`, dead rule)")
        elif compiled.is_unconditional:
            lines.append("- **Condition**: Unconditional (`any`)")
        else:
            lines.append(f"- **Condition**: {len(compiled.dnf_clauses)} DNF clause(s)")
        if compiled.valid_from is not None or compiled.valid_until is not None:
            v_from = format_utc_rfc3339(compiled.valid_from) if compiled.valid_from else "-∞"
            v_until = format_utc_rfc3339(compiled.valid_until) if compiled.valid_until else "+∞"
            lines.append(f"- **Time Window**: `[{v_from}, {v_until})`")

    return "\n".join(lines)


def _prev_code_token(tokens: tuple[LexToken, ...], target: LexToken) -> LexToken | None:
    for idx, tok in enumerate(tokens):
        if tok is target:
            for j in range(idx - 1, -1, -1):
                if tokens[j].kind is not TokenKind.COMMENT:
                    return tokens[j]
            return None
    return None


def _prev_two_code_tokens(
    tokens: tuple[LexToken, ...],
    target: LexToken,
) -> tuple[LexToken | None, LexToken | None]:
    for idx, tok in enumerate(tokens):
        if tok is target:
            found: list[LexToken] = []
            for j in range(idx - 1, -1, -1):
                if tokens[j].kind is not TokenKind.COMMENT:
                    found.append(tokens[j])
                    if len(found) == 2:
                        break
            first = found[0] if len(found) >= 1 else None
            second = found[1] if len(found) >= 2 else None
            return first, second
    return None, None


def get_hover(
    state: DocumentState,
    position: types.Position,
) -> types.Hover | None:
    offset = state.line_index.position_to_offset(position)
    tok = token_at_offset(state.tokens, offset)
    if tok is None or tok.kind is TokenKind.COMMENT:
        return None

    # 1. Atomic operation or preset macro identifier
    if tok.kind is TokenKind.IDENT:
        prev = _prev_code_token(state.tokens, tok)
        subtracted = prev is not None and prev.kind is TokenKind.MINUS
        if tok.value in ATOMIC_OP_BY_NAME:
            md = format_atomic_op_markdown(tok.value, subtracted=subtracted)
            if md:
                return _hover(md, state, tok)
        if tok.value in DEFAULT_PRESET_MACROS:
            md = format_macro_markdown(tok.value, subtracted=subtracted)
            if md:
                return _hover(md, state, tok)
        return None

    # 2. Predicates: user / group / perm
    if tok.kind is TokenKind.PREDICATE:
        md = format_predicate_markdown(tok.value)
        if md:
            return _hover(md, state, tok)
        return None

    # 3. Keywords & Scopes
    if tok.kind is TokenKind.KEYWORD:
        if tok.value in SCOPE_DESCRIPTIONS:
            md = format_scope_markdown(tok.value)
            if md:
                return _hover(md, state, tok)

        base_md = format_keyword_markdown(tok.value)
        if base_md is None:
            return None

        if tok.value in ("allow", "deny"):
            found_rule = _find_rule_at_position(state, position)
            if found_rule is not None:
                rule_idx, rule = found_rule
                compiled = _compiled_rule_at(state, rule_idx)
                base_md = f"{base_md}\n\n{_format_rule_summary(rule, compiled)}"

        return _hover(base_md, state, tok)

    # 4. Operation set brackets -> show resolved rule op summary
    if tok.kind in (TokenKind.LBRACKET, TokenKind.RBRACKET):
        found_rule = _find_rule_at_position(state, position)
        if found_rule is not None:
            rule_idx, rule = found_rule
            compiled = _compiled_rule_at(state, rule_idx)
            mask, all_valid = evaluate_rule_op_mask(rule)
            if all_valid and mask > 0:
                ops = mask_to_atomic_names(mask)
                md = (
                    f"### Operation Set (`0x{mask:06x}`)\n"
                    f"Resolves to **{len(ops)}** atomic operation(s):\n\n"
                    + ", ".join(f"`{op}`" for op in ops)
                )
                if compiled is not None:
                    md += f"\n\n{_format_rule_summary(rule, compiled)}"
                return _hover(md, state, tok)
        return None

    # 5. String literals (timestamps / user UUIDs)
    if tok.kind is TokenKind.STRING and tok.terminated and len(tok.value) >= 2:
        raw_val = tok.value[1:-1]
        prev1, prev2 = _prev_two_code_tokens(state.tokens, tok)

        if prev1 is not None and prev1.value in ("from", "until"):
            parsed = _parse_rfc3339_utc(raw_val)
            if parsed is not None:
                utc_str = format_utc_rfc3339(parsed)
                bound_desc = (
                    "Inclusive start (`>=`)" if prev1.value == "from" else "Exclusive end (`<`)"
                )
                lines = [
                    f"### RFC 3339 Timestamp (`{prev1.value}`)",
                    f"- **Normalized UTC**: `{utc_str}`",
                    f"- **Boundary**: {bound_desc} in half-open interval `[from, until)`",
                ]
                if prev1.value == "until" and parsed <= state.now_utc:
                    lines.append("- **Status**: Expired relative to current UTC time")
                return _hover("\n".join(lines), state, tok)
            return _hover(
                "### Invalid RFC 3339 Timestamp\n"
                'Expected format with explicit timezone, e.g. `"2026-12-31T23:59:59Z"`.',
                state,
                tok,
            )

        if (
            prev1 is not None
            and prev1.kind is TokenKind.LPAREN
            and prev2 is not None
            and prev2.value == "user"
        ):
            parsed_uuid = parse_canonical_uuid(raw_val)
            if parsed_uuid is not None:
                return _hover(
                    "### User Principal UUID\n"
                    f"- **Canonical UUID**: `{parsed_uuid}`\n"
                    "- **Format**: Valid 36-char RFC 9562 UUID",
                    state,
                    tok,
                )
            return _hover(
                "### Invalid User Identifier\n"
                "CACL requires a canonical 36-character hyphenated RFC 9562 UUID "
                '(e.g. `"550e8400-e29b-41d4-a716-446655440000"`).',
                state,
                tok,
            )

    return None
