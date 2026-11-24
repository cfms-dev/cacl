import difflib

from cacl_compiler import ATOMIC_OP_BY_NAME, DEFAULT_PRESET_MACROS, Span
from cacl_compiler.permissions import mask_to_atomic_names, mask_to_folded_tokens
from lsprotocol import types

from .analysis import DocumentState, evaluate_rule_op_mask
from .lexer import TokenKind

_ALL_OP_AND_MACRO_NAMES: tuple[str, ...] = tuple(
    list(DEFAULT_PRESET_MACROS.keys()) + list(ATOMIC_OP_BY_NAME.keys())
)


def _ranges_overlap(a: types.Range, b: types.Range) -> bool:
    a_start = (a.start.line, a.start.character)
    a_end = (a.end.line, a.end.character)
    b_start = (b.start.line, b.start.character)
    b_end = (b.end.line, b.end.character)
    return a_start <= b_end and b_start <= a_end


def _diag_code(diag: types.Diagnostic) -> str | None:
    if isinstance(diag.code, str):
        return diag.code
    if isinstance(diag.data, dict) and isinstance(diag.data.get("code"), str):
        return diag.data["code"]
    return None


def _whole_line_delete_range(state: DocumentState, span: Span) -> types.Range:
    """Expand deletion range to include surrounding blank/newline if span occupies full line(s)."""
    start_off, end_off = state.line_index.span_to_offsets(span)
    src = state.source

    line_start = src.rfind("\n", 0, start_off)
    line_start = 0 if line_start == -1 else line_start + 1
    before_is_ws = src[line_start:start_off].strip() == ""

    line_end = src.find("\n", end_off)
    if line_end == -1:
        after_is_ws = src[end_off:].strip() == ""
        tail_end = len(src)
    else:
        after_is_ws = src[end_off:line_end].strip() == ""
        tail_end = line_end + 1

    if before_is_ws and after_is_ws:
        return types.Range(
            start=state.line_index.offset_to_position(line_start),
            end=state.line_index.offset_to_position(tail_end),
        )
    return state.line_index.span_to_range(span)


def _comma_list_delete_range(
    state: DocumentState,
    item_spans: list[Span],
    target_idx: int,
) -> types.Range:
    """Compute a clean deletion range for item at *target_idx* including its adjacent comma."""
    src = state.source
    start_off, end_off = state.line_index.span_to_offsets(item_spans[target_idx])

    if target_idx > 0:
        prev_end = state.line_index.span_to_offsets(item_spans[target_idx - 1])[1]
        comma_pos = src.find(",", prev_end, start_off)
        if comma_pos != -1:
            return types.Range(
                start=state.line_index.offset_to_position(comma_pos),
                end=state.line_index.offset_to_position(end_off),
            )
    elif target_idx + 1 < len(item_spans):
        next_start = state.line_index.span_to_offsets(item_spans[target_idx + 1])[0]
        comma_pos = src.find(",", end_off, next_start)
        if comma_pos != -1:
            del_end = comma_pos + 1
            while del_end < next_start and src[del_end] in " \t":
                del_end += 1
            return types.Range(
                start=state.line_index.offset_to_position(start_off),
                end=state.line_index.offset_to_position(del_end),
            )

    return state.line_index.span_to_range(item_spans[target_idx])


def _make_edit_action(
    *,
    title: str,
    kind: types.CodeActionKind,
    uri: str,
    edits: list[types.TextEdit],
    diagnostics: list[types.Diagnostic] | None = None,
    is_preferred: bool = False,
) -> types.CodeAction:
    return types.CodeAction(
        title=title,
        kind=kind,
        diagnostics=diagnostics,
        is_preferred=is_preferred,
        edit=types.WorkspaceEdit(changes={uri: edits}),
    )


def _convert_to_perm_quick_fix(
    state: DocumentState,
    diag: types.Diagnostic,
) -> types.CodeAction | None:
    """Detect `to ... perm(...)` and offer rewriting `to` clause into `when ... or ...`."""
    diag_off = state.line_index.position_to_offset(diag.range.start)

    # Locate enclosing statement tokens
    code_tokens = [t for t in state.tokens if t.kind is not TokenKind.COMMENT]
    stmt_start = 0
    stmt_end = len(code_tokens)
    for i, tok in enumerate(code_tokens):
        if tok.kind is TokenKind.SEMI:
            if tok.end_offset <= diag_off:
                stmt_start = i + 1
            elif tok.start_offset >= diag_off:
                stmt_end = i
                break

    stmt = code_tokens[stmt_start:stmt_end]
    to_idx = next((i for i, t in enumerate(stmt) if t.value == "to"), None)
    if to_idx is None:
        return None

    # Find end of the `to` clause (before `from`, `until`, `remark`, or end of stmt)
    clause_end = len(stmt)
    for i in range(to_idx + 1, len(stmt)):
        if stmt[i].value in ("from", "until", "remark"):
            clause_end = i
            break

    clause_tokens = stmt[to_idx + 1 : clause_end]
    if not any(t.kind is TokenKind.PREDICATE and t.value == "perm" for t in clause_tokens):
        return None

    # Split clause_tokens by top-level comma into individual item text slices
    items: list[str] = []
    cur_start: int | None = None
    cur_end: int | None = None
    paren_depth = 0
    for tok in clause_tokens:
        if tok.kind is TokenKind.LPAREN:
            paren_depth += 1
        elif tok.kind is TokenKind.RPAREN:
            paren_depth = max(0, paren_depth - 1)
        elif tok.kind is TokenKind.COMMA and paren_depth == 0:
            if cur_start is not None and cur_end is not None:
                items.append(state.source[cur_start:cur_end].strip())
            cur_start = cur_end = None
            continue

        if cur_start is None:
            cur_start = tok.start_offset
        cur_end = tok.end_offset

    if cur_start is not None and cur_end is not None:
        items.append(state.source[cur_start:cur_end].strip())

    if not items:
        return None

    replace_start = stmt[to_idx].start_offset
    replace_end = clause_tokens[-1].end_offset
    new_text = "when " + " or ".join(items)
    edit = types.TextEdit(
        range=types.Range(
            start=state.line_index.offset_to_position(replace_start),
            end=state.line_index.offset_to_position(replace_end),
        ),
        new_text=new_text,
    )
    return _make_edit_action(
        title="Convert 'to' clause to 'when' clause",
        kind=types.CodeActionKind.QuickFix,
        uri=state.uri,
        edits=[edit],
        diagnostics=[diag],
        is_preferred=True,
    )


def get_code_actions(
    state: DocumentState,
    params: types.CodeActionParams,
) -> list[types.CodeAction]:
    actions: list[types.CodeAction] = []
    req_range = params.range

    # 1. Diagnostic-driven Quick Fixes
    for diag in params.context.diagnostics:
        if not _ranges_overlap(diag.range, req_range):
            continue
        code = _diag_code(diag)
        if code is None:
            continue

        if code == "E201" and state.ast is not None:
            for directive in state.ast.directives[1:]:
                if state.line_index.span_to_range(directive.span) == diag.range:
                    actions.append(
                        _make_edit_action(
                            title="Remove duplicate 'inherit' directive",
                            kind=types.CodeActionKind.QuickFix,
                            uri=state.uri,
                            edits=[
                                types.TextEdit(
                                    range=_whole_line_delete_range(state, directive.span),
                                    new_text="",
                                )
                            ],
                            diagnostics=[diag],
                            is_preferred=True,
                        )
                    )
                    break

        elif code == "E202":
            start_off = state.line_index.position_to_offset(diag.range.start)
            end_off = state.line_index.position_to_offset(diag.range.end)
            raw_text = state.source[start_off:end_off].strip()
            has_minus = raw_text.startswith("-")
            ident = raw_text[1:].strip() if has_minus else raw_text
            matches = difflib.get_close_matches(
                ident.upper(), _ALL_OP_AND_MACRO_NAMES, n=3, cutoff=0.5
            )
            for idx, suggestion in enumerate(matches):
                replacement = f"-{suggestion}" if has_minus else suggestion
                actions.append(
                    _make_edit_action(
                        title=f"Replace with '{replacement}'",
                        kind=types.CodeActionKind.QuickFix,
                        uri=state.uri,
                        edits=[types.TextEdit(range=diag.range, new_text=replacement)],
                        diagnostics=[diag],
                        is_preferred=(idx == 0),
                    )
                )

        elif code in ("E205", "E101"):
            fix = _convert_to_perm_quick_fix(state, diag)
            if fix is not None:
                actions.append(fix)

        elif code in ("W201", "W202") and state.ast is not None:
            for rule in state.ast.rules:
                if len(rule.op_items) <= 1:
                    continue
                item_spans = [item.span for item in rule.op_items]
                for idx, item in enumerate(rule.op_items):
                    if state.line_index.span_to_range(item.span) == diag.range:
                        label = f"-{item.name}" if item.subtract else item.name
                        del_range = _comma_list_delete_range(state, item_spans, idx)
                        actions.append(
                            _make_edit_action(
                                title=f"Remove redundant operation '{label}'",
                                kind=types.CodeActionKind.QuickFix,
                                uri=state.uri,
                                edits=[types.TextEdit(range=del_range, new_text="")],
                                diagnostics=[diag],
                                is_preferred=True,
                            )
                        )
                        break

        elif code == "W208" and state.ast is not None:
            for rule in state.ast.rules:
                if rule.match.syntax != "to" or len(rule.match.to_items) <= 1:
                    continue
                item_spans = [item.span for item in rule.match.to_items]
                for idx, item in enumerate(rule.match.to_items):
                    if state.line_index.span_to_range(item.span) == diag.range:
                        del_range = _comma_list_delete_range(state, item_spans, idx)
                        actions.append(
                            _make_edit_action(
                                title="Remove duplicate principal",
                                kind=types.CodeActionKind.QuickFix,
                                uri=state.uri,
                                edits=[types.TextEdit(range=del_range, new_text="")],
                                diagnostics=[diag],
                                is_preferred=True,
                            )
                        )
                        break

        elif code == "W211" and state.ast is not None:
            for rule in state.ast.rules:
                if state.line_index.span_to_range(rule.span) == diag.range:
                    actions.append(
                        _make_edit_action(
                            title="Remove duplicate rule",
                            kind=types.CodeActionKind.QuickFix,
                            uri=state.uri,
                            edits=[
                                types.TextEdit(
                                    range=_whole_line_delete_range(state, rule.span),
                                    new_text="",
                                )
                            ],
                            diagnostics=[diag],
                            is_preferred=True,
                        )
                    )
                    break

    # 2. Refactoring actions on valid operation sets
    if state.ast is not None:
        for rule in state.ast.rules:
            op_range = state.line_index.span_to_range(rule.op_set_span)
            if not _ranges_overlap(op_range, req_range):
                continue
            mask, all_valid = evaluate_rule_op_mask(rule)
            if not all_valid or mask <= 0:
                continue

            current_raw = state.source[
                state.line_index.position_to_offset(op_range.start) : state.line_index.position_to_offset(op_range.end)
            ]
            expanded = "[" + ", ".join(mask_to_atomic_names(mask)) + "]"
            folded = "[" + ", ".join(mask_to_folded_tokens(mask)) + "]"

            if expanded != current_raw:
                actions.append(
                    _make_edit_action(
                        title="Expand operation set to atomic operations",
                        kind=types.CodeActionKind.RefactorRewrite,
                        uri=state.uri,
                        edits=[types.TextEdit(range=op_range, new_text=expanded)],
                    )
                )
            if folded != current_raw and folded != expanded:
                actions.append(
                    _make_edit_action(
                        title="Fold operation set using preset macros",
                        kind=types.CodeActionKind.RefactorRewrite,
                        uri=state.uri,
                        edits=[types.TextEdit(range=op_range, new_text=folded)],
                    )
                )

    return actions
