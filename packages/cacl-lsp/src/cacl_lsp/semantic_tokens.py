from cacl_compiler import ATOMIC_OP_BY_NAME, DEFAULT_PRESET_MACROS
from lsprotocol import types

from .analysis import DocumentState
from .coordinates import codepoint_col_to_utf16, utf16_len
from .lexer import TokenKind

SEMANTIC_TOKEN_TYPES: tuple[str, ...] = (
    "keyword",
    "operator",
    "macro",
    "enumMember",
    "type",
    "function",
    "string",
    "comment",
    "variable",
)

SEMANTIC_TOKEN_MODIFIERS: tuple[str, ...] = (
    "readonly",
    "modification",
)

SEMANTIC_TOKEN_LEGEND = types.SemanticTokensLegend(
    token_types=list(SEMANTIC_TOKEN_TYPES),
    token_modifiers=list(SEMANTIC_TOKEN_MODIFIERS),
)

_TYPE_IDX: dict[str, int] = {name: i for i, name in enumerate(SEMANTIC_TOKEN_TYPES)}
_MOD_READONLY = 1 << 0
_MOD_MODIFICATION = 1 << 1

_LOGICAL_OPS: frozenset[str] = frozenset({"and", "or", "not"})
_SCOPE_NAMES: frozenset[str] = frozenset({"self", "dirs", "docs", "all"})


def get_semantic_tokens(state: DocumentState) -> types.SemanticTokens:
    raw_tokens: list[tuple[int, int, int, int, int]] = []

    in_op_set = False
    after_minus = False
    after_inherit = False

    for tok in state.tokens:
        line_0 = tok.line - 1
        line_str = state.line_index.line_text(line_0)
        start_utf16 = codepoint_col_to_utf16(line_str, tok.column - 1)
        length_utf16 = utf16_len(tok.value)
        if length_utf16 <= 0:
            continue

        if tok.kind is TokenKind.COMMENT:
            raw_tokens.append((line_0, start_utf16, length_utf16, _TYPE_IDX["comment"], 0))
            continue

        if tok.kind is TokenKind.LBRACKET:
            in_op_set = True
            after_minus = False
            after_inherit = False
            continue
        if tok.kind is TokenKind.RBRACKET:
            in_op_set = False
            after_minus = False
            after_inherit = False
            continue
        if tok.kind is TokenKind.SEMI:
            in_op_set = False
            after_minus = False
            after_inherit = False
            continue
        if tok.kind is TokenKind.MINUS:
            if in_op_set:
                after_minus = True
            raw_tokens.append((line_0, start_utf16, length_utf16, _TYPE_IDX["operator"], 0))
            continue
        if tok.kind is TokenKind.COMMA:
            after_minus = False
            continue

        if tok.kind is TokenKind.IDENT:
            mods = _MOD_MODIFICATION if (in_op_set and after_minus) else 0
            after_minus = False
            if tok.value in DEFAULT_PRESET_MACROS:
                t_idx = _TYPE_IDX["macro"]
            elif tok.value in ATOMIC_OP_BY_NAME:
                t_idx = _TYPE_IDX["enumMember"]
            else:
                t_idx = _TYPE_IDX["variable"]
            raw_tokens.append((line_0, start_utf16, length_utf16, t_idx, mods))
            continue

        after_minus = False

        if tok.kind is TokenKind.PREDICATE:
            after_inherit = False
            raw_tokens.append((line_0, start_utf16, length_utf16, _TYPE_IDX["function"], 0))
            continue

        if tok.kind is TokenKind.STRING:
            after_inherit = False
            raw_tokens.append((line_0, start_utf16, length_utf16, _TYPE_IDX["string"], 0))
            continue

        if tok.kind is TokenKind.KEYWORD:
            val = tok.value
            if val == "inherit":
                after_inherit = True
                raw_tokens.append((line_0, start_utf16, length_utf16, _TYPE_IDX["keyword"], 0))
            elif after_inherit and val in ("on", "off"):
                after_inherit = False
                raw_tokens.append(
                    (line_0, start_utf16, length_utf16, _TYPE_IDX["keyword"], _MOD_READONLY)
                )
            else:
                after_inherit = False
                if val in _LOGICAL_OPS:
                    raw_tokens.append(
                        (line_0, start_utf16, length_utf16, _TYPE_IDX["operator"], 0)
                    )
                elif val in _SCOPE_NAMES:
                    raw_tokens.append(
                        (line_0, start_utf16, length_utf16, _TYPE_IDX["type"], 0)
                    )
                elif val == "any":
                    raw_tokens.append(
                        (line_0, start_utf16, length_utf16, _TYPE_IDX["keyword"], _MOD_READONLY)
                    )
                else:
                    raw_tokens.append(
                        (line_0, start_utf16, length_utf16, _TYPE_IDX["keyword"], 0)
                    )
            continue

        after_inherit = False

    # Delta-encode sorted tokens
    raw_tokens.sort(key=lambda item: (item[0], item[1]))
    data: list[int] = []
    prev_line = 0
    prev_start = 0
    for line_0, start_utf16, length_utf16, t_idx, mods in raw_tokens:
        delta_line = line_0 - prev_line
        delta_start = start_utf16 - prev_start if delta_line == 0 else start_utf16
        data.extend((delta_line, delta_start, length_utf16, t_idx, mods))
        prev_line = line_0
        prev_start = start_utf16

    return types.SemanticTokens(data=data)
