import re
from dataclasses import dataclass
from enum import StrEnum

from cacl_compiler import Span


class TokenKind(StrEnum):
    COMMENT = "COMMENT"
    STRING = "STRING"
    IDENT = "IDENT"
    KEYWORD = "KEYWORD"
    PREDICATE = "PREDICATE"
    WORD = "WORD"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COMMA = "COMMA"
    SEMI = "SEMI"
    MINUS = "MINUS"
    UNKNOWN = "UNKNOWN"


CACL_KEYWORDS: frozenset[str] = frozenset({
    "inherit",
    "on",
    "off",
    "allow",
    "deny",
    "self",
    "dirs",
    "docs",
    "all",
    "to",
    "when",
    "from",
    "until",
    "remark",
    "and",
    "or",
    "not",
    "any",
})

CACL_PREDICATES: frozenset[str] = frozenset({"user", "group", "perm"})

_PUNCT_MAP: dict[str, TokenKind] = {
    "[": TokenKind.LBRACKET,
    "]": TokenKind.RBRACKET,
    "(": TokenKind.LPAREN,
    ")": TokenKind.RPAREN,
    ",": TokenKind.COMMA,
    ";": TokenKind.SEMI,
    "-": TokenKind.MINUS,
}

_TOKEN_RE = re.compile(
    r"(?P<NEWLINE>\r\n|\n|\r)"
    r"|(?P<WS>[ \t]+)"
    r"|(?P<COMMENT>#[^\r\n]*)"
    r'|(?P<STRING>"(?:[^"\\\r\n]|\\.)*")'
    r'|(?P<UNTERM_STRING>"(?:[^"\\\r\n]|\\.)*)'
    r"|(?P<IDENT>[A-Z][A-Z0-9_]*)"
    r"|(?P<WORD>[a-z_][a-zA-Z0-9_]*)"
    r"|(?P<PUNCT>[\[\](),;-])"
    r"|(?P<UNKNOWN>.)"
)


@dataclass(frozen=True, slots=True)
class LexToken:
    kind: TokenKind
    value: str
    start_offset: int
    end_offset: int
    line: int
    column: int
    end_line: int
    end_column: int
    terminated: bool = True

    @property
    def span(self) -> Span:
        return Span(
            line=self.line,
            column=self.column,
            end_line=self.end_line,
            end_column=self.end_column,
        )


def tokenize_cacl(source: str) -> tuple[LexToken, ...]:
    """Fault-tolerant tokenizer mirroring cacl.lark lexical rules."""
    tokens: list[LexToken] = []
    line = 1
    line_start = 0

    for match in _TOKEN_RE.finditer(source):
        group = match.lastgroup
        start = match.start()
        end = match.end()
        text = match.group()

        if group == "NEWLINE":
            line += 1
            line_start = end
            continue
        if group == "WS":
            continue

        col = start - line_start + 1
        end_col = end - line_start + 1

        if group == "COMMENT":
            kind = TokenKind.COMMENT
            terminated = True
        elif group == "STRING":
            kind = TokenKind.STRING
            terminated = True
        elif group == "UNTERM_STRING":
            kind = TokenKind.STRING
            terminated = False
        elif group == "IDENT":
            kind = TokenKind.IDENT
            terminated = True
        elif group == "WORD":
            if text in CACL_PREDICATES:
                kind = TokenKind.PREDICATE
            elif text in CACL_KEYWORDS:
                kind = TokenKind.KEYWORD
            else:
                kind = TokenKind.WORD
            terminated = True
        elif group == "PUNCT":
            kind = _PUNCT_MAP[text]
            terminated = True
        else:
            kind = TokenKind.UNKNOWN
            terminated = True

        tokens.append(
            LexToken(
                kind=kind,
                value=text,
                start_offset=start,
                end_offset=end,
                line=line,
                column=col,
                end_line=line,
                end_column=end_col,
                terminated=terminated,
            )
        )

    return tuple(tokens)


def token_at_offset(tokens: tuple[LexToken, ...], offset: int) -> LexToken | None:
    """Find the token covering *offset* (inclusive of start, inclusive of end for identifier touch)."""
    # Prefer strictly containing token first
    for tok in tokens:
        if tok.start_offset <= offset < tok.end_offset:
            return tok
    # Fallback: cursor right at the end of a word/ident/keyword/predicate
    for tok in tokens:
        if tok.end_offset == offset and tok.kind in (
            TokenKind.IDENT,
            TokenKind.KEYWORD,
            TokenKind.PREDICATE,
            TokenKind.WORD,
            TokenKind.STRING,
        ):
            return tok
    return None
