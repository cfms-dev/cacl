from datetime import timedelta

from cacl_compiler import ATOMIC_OP_BY_NAME, DEFAULT_PRESET_MACROS
from cacl_compiler.permissions import ATOMIC_OP_TABLE, mask_to_atomic_names
from lsprotocol import types

from .analysis import DocumentState
from .docs import (
    KEYWORD_DESCRIPTIONS,
    PREDICATE_DESCRIPTIONS,
    SCOPE_DESCRIPTIONS,
    format_atomic_op_markdown,
    format_macro_markdown,
)
from .lexer import LexToken, TokenKind


def _md(text: str) -> types.MarkupContent:
    return types.MarkupContent(kind=types.MarkupKind.Markdown, value=text)


def _op_items(*, subtract_present_mask: int | None = None) -> list[types.CompletionItem]:
    items: list[types.CompletionItem] = []

    for macro_name, macro_mask in DEFAULT_PRESET_MACROS.items():
        ops = mask_to_atomic_names(macro_mask)
        is_present = (
            subtract_present_mask is not None
            and (subtract_present_mask & macro_mask) == macro_mask
        )
        prefix = "0_" if (subtract_present_mask is None or is_present) else "2_"
        items.append(
            types.CompletionItem(
                label=macro_name,
                kind=types.CompletionItemKind.Constant,
                detail=f"Preset macro (0x{macro_mask:06x}, {len(ops)} ops)",
                documentation=_md(format_macro_markdown(macro_name) or ""),
                sort_text=f"{prefix}macro_{macro_name}",
            )
        )

    for meta in ATOMIC_OP_TABLE:
        bit_val = int(meta.op)
        is_present = (
            subtract_present_mask is not None and bool(subtract_present_mask & bit_val)
        )
        if subtract_present_mask is not None:
            prefix = "0_" if is_present else "3_"
        else:
            prefix = "1_"
        items.append(
            types.CompletionItem(
                label=meta.name,
                kind=types.CompletionItemKind.EnumMember,
                detail=f"AtomicOp bit {meta.bit_offset} (0x{bit_val:06x}, {meta.target.value})",
                documentation=_md(format_atomic_op_markdown(meta.name) or ""),
                sort_text=f"{prefix}op_{meta.bit_offset:02d}_{meta.name}",
            )
        )

    return items


def _keyword_item(
    label: str,
    *,
    insert_text: str | None = None,
    snippet: bool = False,
    detail: str = "CACL keyword",
    documentation: str | None = None,
    sort_prefix: str = "1_",
) -> types.CompletionItem:
    return types.CompletionItem(
        label=label,
        kind=types.CompletionItemKind.Keyword,
        detail=detail,
        documentation=_md(documentation) if documentation else None,
        insert_text=insert_text,
        insert_text_format=(
            types.InsertTextFormat.Snippet
            if snippet
            else types.InsertTextFormat.PlainText
        ),
        sort_text=f"{sort_prefix}{label}",
    )


def _predicate_items(*, include_perm: bool) -> list[types.CompletionItem]:
    items = [
        types.CompletionItem(
            label="user",
            kind=types.CompletionItemKind.Function,
            detail='user("<uuid>")',
            documentation=_md(PREDICATE_DESCRIPTIONS["user"]),
            insert_text='user("${1:00000000-0000-4000-8000-000000000000}")',
            insert_text_format=types.InsertTextFormat.Snippet,
            sort_text="0_user",
        ),
        types.CompletionItem(
            label="group",
            kind=types.CompletionItemKind.Function,
            detail='group("<group_id>")',
            documentation=_md(PREDICATE_DESCRIPTIONS["group"]),
            insert_text='group("${1:group_name}")',
            insert_text_format=types.InsertTextFormat.Snippet,
            sort_text="0_group",
        ),
    ]
    if include_perm:
        items.append(
            types.CompletionItem(
                label="perm",
                kind=types.CompletionItemKind.Function,
                detail='perm("<capability>")',
                documentation=_md(PREDICATE_DESCRIPTIONS["perm"]),
                insert_text='perm("${1:capability}")',
                insert_text_format=types.InsertTextFormat.Snippet,
                sort_text="0_perm",
            )
        )
    items.append(
        _keyword_item(
            "any",
            detail="Matches every subject",
            documentation=KEYWORD_DESCRIPTIONS["any"],
            sort_prefix="1_",
        )
    )
    return items


def _timestamp_items(state: DocumentState, *, quoted: bool) -> list[types.CompletionItem]:
    now = state.now_utc.replace(second=0, microsecond=0)
    end_of_day = now.replace(hour=23, minute=59, second=59)
    plus_30d = now + timedelta(days=30)

    def wrap(val: str) -> str:
        return f'"{val}"' if quoted else val

    now_s = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    eod_s = end_of_day.strftime("%Y-%m-%dT%H:%M:%SZ")
    p30_s = plus_30d.strftime("%Y-%m-%dT%H:%M:%SZ")

    return [
        types.CompletionItem(
            label=now_s,
            kind=types.CompletionItemKind.Value,
            detail="Current UTC timestamp (RFC 3339)",
            insert_text=wrap(now_s),
            sort_text="0_now",
        ),
        types.CompletionItem(
            label=eod_s,
            kind=types.CompletionItemKind.Value,
            detail="End of today UTC (RFC 3339)",
            insert_text=wrap(eod_s),
            sort_text="1_eod",
        ),
        types.CompletionItem(
            label=p30_s,
            kind=types.CompletionItemKind.Value,
            detail="+30 days UTC (RFC 3339)",
            insert_text=wrap(p30_s),
            sort_text="2_plus30d",
        ),
        types.CompletionItem(
            label="RFC 3339 timestamp template",
            kind=types.CompletionItemKind.Snippet,
            detail="Custom UTC timestamp",
            insert_text=wrap("${1:2026}-${2:12}-${3:31}T${4:23:59:59}Z"),
            insert_text_format=types.InsertTextFormat.Snippet,
            sort_text="3_template",
        ),
    ]


def _scope_items() -> list[types.CompletionItem]:
    return [
        types.CompletionItem(
            label=name,
            kind=types.CompletionItemKind.EnumMember,
            detail=f"Scope: on {name}",
            documentation=_md(desc),
            sort_text=f"0_{idx}_{name}",
        )
        for idx, (name, desc) in enumerate(SCOPE_DESCRIPTIONS.items())
    ]


def _statement_start_items(
    *,
    allow_inherit: bool,
) -> list[types.CompletionItem]:
    items: list[types.CompletionItem] = []
    if allow_inherit:
        items.append(
            _keyword_item(
                "inherit",
                detail="Inheritance directive",
                documentation=KEYWORD_DESCRIPTIONS["inherit"],
                sort_prefix="0_",
            )
        )
        items.append(
            types.CompletionItem(
                label="inherit on;",
                kind=types.CompletionItemKind.Snippet,
                detail="Enable ancestor inheritance",
                documentation=_md(KEYWORD_DESCRIPTIONS["inherit"]),
                insert_text="inherit ${1|on,off|};",
                insert_text_format=types.InsertTextFormat.Snippet,
                sort_text="0_inherit_snippet",
            )
        )

    items.extend([
        _keyword_item(
            "allow",
            detail="Allow rule",
            documentation=KEYWORD_DESCRIPTIONS["allow"],
            sort_prefix="1_",
        ),
        _keyword_item(
            "deny",
            detail="Deny rule (overrides allow)",
            documentation=KEYWORD_DESCRIPTIONS["deny"],
            sort_prefix="1_",
        ),
        types.CompletionItem(
            label="allow rule (to)",
            kind=types.CompletionItemKind.Snippet,
            detail="Allow rule with principal list",
            insert_text='allow [${1:PRESET_READ}] on ${2|all,self,dirs,docs|} to ${3:group("name")};',
            insert_text_format=types.InsertTextFormat.Snippet,
            sort_text="2_allow_to",
        ),
        types.CompletionItem(
            label="deny rule (when)",
            kind=types.CompletionItemKind.Snippet,
            detail="Deny rule with boolean condition",
            insert_text='deny [${1:DELETE}] on ${2|all,self,dirs,docs|} when ${3:not group("admins")};',
            insert_text_format=types.InsertTextFormat.Snippet,
            sort_text="2_deny_when",
        ),
    ])
    return items


def _accumulated_mask_in_op_set(stmt_tokens: list[LexToken]) -> int:
    """Estimate currently added bits inside the active `[...]` operation set."""
    lbracket_idx = -1
    for i in range(len(stmt_tokens) - 1, -1, -1):
        if stmt_tokens[i].kind is TokenKind.LBRACKET:
            lbracket_idx = i
            break
    if lbracket_idx == -1:
        return 0

    mask = 0
    subtract_next = False
    for tok in stmt_tokens[lbracket_idx + 1 :]:
        if tok.kind is TokenKind.MINUS:
            subtract_next = True
            continue
        if tok.kind is TokenKind.IDENT:
            meta = ATOMIC_OP_BY_NAME.get(tok.value)
            item_mask = (
                int(meta.op)
                if meta is not None
                else DEFAULT_PRESET_MACROS.get(tok.value, 0)
            )
            if subtract_next:
                mask &= ~item_mask
            else:
                mask |= item_mask
            subtract_next = False
        elif tok.kind is TokenKind.COMMA:
            subtract_next = False
    return mask


def get_completions(
    state: DocumentState,
    position: types.Position,
) -> types.CompletionList:
    offset = state.line_index.position_to_offset(position)

    # 1. Check if cursor is inside a comment or string token
    for idx, tok in enumerate(state.tokens):
        if tok.kind is TokenKind.COMMENT and tok.start_offset <= offset <= tok.end_offset:
            return types.CompletionList(is_incomplete=False, items=[])

        if tok.kind is TokenKind.STRING:
            inside = (
                tok.start_offset < offset < tok.end_offset
                if tok.terminated
                else tok.start_offset < offset <= tok.end_offset
            )
            if inside:
                prev = _prev_code_token(state.tokens, idx)
                if prev is not None and prev.value in ("from", "until"):
                    return types.CompletionList(
                        is_incomplete=False,
                        items=_timestamp_items(state, quoted=False),
                    )
                return types.CompletionList(is_incomplete=False, items=[])

    # 2. Gather non-comment tokens strictly preceding the token being typed at `offset`
    code_before: list[LexToken] = []
    for tok in state.tokens:
        if tok.kind is TokenKind.COMMENT:
            continue
        if tok.start_offset >= offset:
            break
        # If cursor is inside/at the end of an identifier/word being typed, exclude it as prefix
        if tok.start_offset < offset <= tok.end_offset and tok.kind in (
            TokenKind.IDENT,
            TokenKind.KEYWORD,
            TokenKind.PREDICATE,
            TokenKind.WORD,
        ):
            break
        code_before.append(tok)

    # Slice current statement (after the last semicolon)
    last_semi = -1
    for i, tok in enumerate(code_before):
        if tok.kind is TokenKind.SEMI:
            last_semi = i
    stmt = code_before[last_semi + 1 :]

    # Statement start
    if not stmt:
        has_inherit = any(t.value == "inherit" for t in state.tokens if t.kind is TokenKind.KEYWORD)
        has_rule_before = any(
            t.value in ("allow", "deny") for t in code_before if t.kind is TokenKind.KEYWORD
        )
        return types.CompletionList(
            is_incomplete=False,
            items=_statement_start_items(allow_inherit=not has_inherit and not has_rule_before),
        )

    # Inside `[ ... ]` operation set?
    bracket_depth = 0
    for tok in stmt:
        if tok.kind is TokenKind.LBRACKET:
            bracket_depth += 1
        elif tok.kind is TokenKind.RBRACKET:
            bracket_depth = max(0, bracket_depth - 1)

    last = stmt[-1]

    if bracket_depth > 0:
        if last.kind is TokenKind.MINUS:
            present = _accumulated_mask_in_op_set(stmt[:-1])
            return types.CompletionList(
                is_incomplete=False,
                items=_op_items(subtract_present_mask=present),
            )
        if last.kind in (TokenKind.LBRACKET, TokenKind.COMMA):
            return types.CompletionList(is_incomplete=False, items=_op_items())
        # After an operation identifier inside `[...]` nothing keyword-like is expected
        return types.CompletionList(is_incomplete=False, items=[])

    # Directive: `inherit <on|off>`
    if stmt[0].value == "inherit":
        if len(stmt) == 1:
            return types.CompletionList(
                is_incomplete=False,
                items=[
                    _keyword_item(
                        "on",
                        detail="Enable inheritance",
                        documentation=KEYWORD_DESCRIPTIONS["on"],
                        sort_prefix="0_",
                    ),
                    _keyword_item(
                        "off",
                        detail="Disable inheritance",
                        documentation=KEYWORD_DESCRIPTIONS["off"],
                        sort_prefix="1_",
                    ),
                ],
            )
        return types.CompletionList(is_incomplete=False, items=[])

    # Rule clauses
    if last.value == "on":
        return types.CompletionList(is_incomplete=False, items=_scope_items())

    if last.value in ("from", "until"):
        return types.CompletionList(
            is_incomplete=False,
            items=_timestamp_items(state, quoted=True),
        )

    if last.value == "remark":
        return types.CompletionList(
            is_incomplete=False,
            items=[
                types.CompletionItem(
                    label='"remark"',
                    kind=types.CompletionItemKind.Snippet,
                    detail="Rule audit remark",
                    insert_text='"${1:Audit reason}"',
                    insert_text_format=types.InsertTextFormat.Snippet,
                )
            ],
        )

    # Track clause progression within the rule
    has_rbracket = any(t.kind is TokenKind.RBRACKET for t in stmt)
    has_on = any(t.value == "on" for t in stmt)
    has_to = any(t.value == "to" for t in stmt)
    has_when = any(t.value == "when" for t in stmt)
    has_from = any(t.value == "from" for t in stmt)
    has_until = any(t.value == "until" for t in stmt)
    has_remark = any(t.value == "remark" for t in stmt)

    if not has_rbracket:
        return types.CompletionList(is_incomplete=False, items=[])

    # Right after `]` or `on <scope>`
    if not has_to and not has_when:
        items: list[types.CompletionItem] = []
        if not has_on:
            items.append(
                _keyword_item(
                    "on",
                    detail="Target scope (self | dirs | docs | all)",
                    documentation=KEYWORD_DESCRIPTIONS["on"],
                    sort_prefix="0_",
                )
            )
        items.append(
            _keyword_item(
                "to",
                detail="Principal list shorthand",
                documentation=KEYWORD_DESCRIPTIONS["to"],
                sort_prefix="1_",
            )
        )
        items.append(
            _keyword_item(
                "when",
                detail="Boolean condition expression",
                documentation=KEYWORD_DESCRIPTIONS["when"],
                sort_prefix="1_",
            )
        )
        return types.CompletionList(is_incomplete=False, items=items)

    # Inside `to` clause (before `from`/`until`/`remark`)
    if has_to and not has_from and not has_until and not has_remark:
        if last.value == "to" or last.kind is TokenKind.COMMA:
            return types.CompletionList(
                is_incomplete=False,
                items=_predicate_items(include_perm=False),
            )
        return types.CompletionList(
            is_incomplete=False,
            items=_trailing_clause_items(has_from=False, has_until=False, has_remark=False),
        )

    # Inside `when` clause (before `from`/`until`/`remark`)
    if has_when and not has_from and not has_until and not has_remark:
        if last.value in ("when", "and", "or", "not") or last.kind is TokenKind.LPAREN:
            items = _predicate_items(include_perm=True)
            items.append(
                _keyword_item(
                    "not",
                    detail="Boolean negation",
                    documentation=KEYWORD_DESCRIPTIONS["not"],
                    sort_prefix="2_",
                )
            )
            return types.CompletionList(is_incomplete=False, items=items)
        # After a complete atom (`)` or `any`): allow boolean operators or trailing clauses
        items = [
            _keyword_item(
                "and",
                detail="Boolean conjunction",
                documentation=KEYWORD_DESCRIPTIONS["and"],
                sort_prefix="0_",
            ),
            _keyword_item(
                "or",
                detail="Boolean disjunction",
                documentation=KEYWORD_DESCRIPTIONS["or"],
                sort_prefix="0_",
            ),
        ]
        items.extend(
            _trailing_clause_items(has_from=False, has_until=False, has_remark=False)
        )
        return types.CompletionList(is_incomplete=False, items=items)

    # After `from "..."` / `until "..."` / `remark "..."`
    return types.CompletionList(
        is_incomplete=False,
        items=_trailing_clause_items(
            has_from=has_from,
            has_until=has_until,
            has_remark=has_remark,
        ),
    )


def _trailing_clause_items(
    *,
    has_from: bool,
    has_until: bool,
    has_remark: bool,
) -> list[types.CompletionItem]:
    if has_remark:
        return []
    items: list[types.CompletionItem] = []
    if not has_from and not has_until:
        items.append(
            _keyword_item(
                "from",
                detail="Valid-from RFC 3339 timestamp",
                documentation=KEYWORD_DESCRIPTIONS["from"],
                sort_prefix="2_",
            )
        )
    if not has_until:
        items.append(
            _keyword_item(
                "until",
                detail="Valid-until RFC 3339 timestamp",
                documentation=KEYWORD_DESCRIPTIONS["until"],
                sort_prefix="2_",
            )
        )
    items.append(
        _keyword_item(
            "remark",
            detail="Audit remark string",
            documentation=KEYWORD_DESCRIPTIONS["remark"],
            sort_prefix="3_",
        )
    )
    return items


def _prev_code_token(tokens: tuple[LexToken, ...], idx: int) -> LexToken | None:
    for i in range(idx - 1, -1, -1):
        if tokens[i].kind is not TokenKind.COMMENT:
            return tokens[i]
    return None
