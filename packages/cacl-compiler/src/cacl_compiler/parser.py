from dataclasses import dataclass

from lark import Lark, Token, Transformer, UnexpectedInput, v_args

from .ast_nodes import (
    AnyExprNode,
    BinaryExprNode,
    Effect,
    ExprNode,
    InheritDirectiveNode,
    MatchClauseNode,
    NotExprNode,
    OpItemNode,
    PolicyAST,
    PredicateExprNode,
    PredicateKind,
    RuleNode,
    Scope,
    TimeWindowNode,
)
from .diagnostics import Diagnostic, Severity, Span

_ESCAPE_MAP: dict[str, str] = {
    '"': '"',
    "\\": "\\",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _meta_span(meta) -> Span:
    if meta is None or getattr(meta, "empty", False):
        return Span(1, 1, 1, 1)
    return Span(
        line=meta.line,
        column=meta.column,
        end_line=meta.end_line,
        end_column=meta.end_column,
    )


def _token_span(tok: Token) -> Span:
    return Span(
        line=tok.line or 1,
        column=tok.column or 1,
        end_line=tok.end_line or (tok.line or 1),
        end_column=tok.end_column or ((tok.column or 1) + len(tok.value)),
    )


def unescape_cacl_string(tok: Token, diagnostics: list[Diagnostic]) -> str:
    """Strictly unescape CACL string literals supporting \\\", \\\\, \\n, \\r, \\t."""
    raw = tok.value[1:-1]
    out: list[str] = []
    i = 0
    base_line = tok.line or 1
    base_col = (tok.column or 1) + 1  # skip opening quote
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            if i + 1 >= len(raw):
                diagnostics.append(
                    Diagnostic(
                        code="E102",
                        severity=Severity.ERROR,
                        message="Unterminated escape sequence in string literal.",
                        span=Span(base_line, base_col + i, base_line, base_col + i + 1),
                    )
                )
                break
            nxt = raw[i + 1]
            mapped = _ESCAPE_MAP.get(nxt)
            if mapped is None:
                diagnostics.append(
                    Diagnostic(
                        code="E102",
                        severity=Severity.ERROR,
                        message=f"Unsupported escape sequence '\\{nxt}' in string literal.",
                        span=Span(base_line, base_col + i, base_line, base_col + i + 2),
                        hint=r"Allowed escapes in CACL are: \", \\, \n, \r, \t.",
                    )
                )
                out.append(nxt)
            else:
                out.append(mapped)
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass(frozen=True, slots=True)
class _ToList:
    items: tuple[ExprNode, ...]
    span: Span


@dataclass(frozen=True, slots=True)
class _ScopeSpec:
    scope: Scope
    span: Span


class _ASTBuilder(Transformer):
    def __init__(self, diagnostics: list[Diagnostic]) -> None:
        super().__init__()
        self._diagnostics = diagnostics

    def start(self, children):
        directives: list[InheritDirectiveNode] = []
        rules: list[RuleNode] = []
        for stmt in children:
            if isinstance(stmt, InheritDirectiveNode):
                directives.append(stmt)
            elif isinstance(stmt, RuleNode):
                rules.append(stmt)
        return PolicyAST(directives=tuple(directives), rules=tuple(rules))

    # NOTE: handlers mirror the normative grammar in cacl.lark (CEP 2).
    # Anonymous keyword/punctuation tokens are filtered out by Lark, and `?rule`
    # productions with a single child are inlined, so children are positional
    # values of the *named* sub-rules only.

    @v_args(meta=True)
    def directive(self, meta, children):
        return InheritDirectiveNode(enabled=children[0], span=_meta_span(meta))

    def inherit_on(self, children):
        return True

    def inherit_off(self, children):
        return False

    def effect_allow(self, children):
        return Effect.ALLOW

    def effect_deny(self, children):
        return Effect.DENY

    @v_args(meta=True)
    def op_add(self, meta, children):
        return OpItemNode(name=children[0].value, subtract=False, span=_meta_span(meta))

    @v_args(meta=True)
    def op_sub(self, meta, children):
        return OpItemNode(name=children[0].value, subtract=True, span=_meta_span(meta))

    @v_args(meta=True)
    def op_set(self, meta, children):
        return (tuple(children), _meta_span(meta))

    @v_args(meta=True)
    def scope_self(self, meta, children):
        return _ScopeSpec(scope=Scope.SELF, span=_meta_span(meta))

    @v_args(meta=True)
    def scope_dirs(self, meta, children):
        return _ScopeSpec(scope=Scope.DIRS, span=_meta_span(meta))

    @v_args(meta=True)
    def scope_docs(self, meta, children):
        return _ScopeSpec(scope=Scope.DOCS, span=_meta_span(meta))

    @v_args(meta=True)
    def scope_all(self, meta, children):
        return _ScopeSpec(scope=Scope.ALL, span=_meta_span(meta))

    @v_args(meta=True)
    def principal_pred(self, meta, children):
        kind_tok, str_tok = children
        return PredicateExprNode(
            kind=PredicateKind(kind_tok.value),
            raw_value=unescape_cacl_string(str_tok, self._diagnostics),
            span=_meta_span(meta),
        )

    @v_args(meta=True)
    def perm_pred(self, meta, children):
        kind_tok, str_tok = children
        return PredicateExprNode(
            kind=PredicateKind.PERM,
            raw_value=unescape_cacl_string(str_tok, self._diagnostics),
            span=_meta_span(meta),
        )

    @v_args(meta=True)
    def any_pred(self, meta, children):
        return AnyExprNode(span=_meta_span(meta))

    @v_args(meta=True)
    def principal_list(self, meta, children):
        return _ToList(items=tuple(children), span=_meta_span(meta))

    @staticmethod
    def _fold(op: str, items):
        expr = items[0]
        for nxt in items[1:]:
            expr = BinaryExprNode(
                op=op,
                left=expr,
                right=nxt,
                span=Span(
                    expr.span.line,
                    expr.span.column,
                    nxt.span.end_line,
                    nxt.span.end_column,
                ),
            )
        return expr

    # Only produced when there are >= 2 operands (single child is inlined).
    def or_expr(self, children):
        return self._fold("or", children)

    def and_expr(self, children):
        return self._fold("and", children)

    @v_args(meta=True)
    def neg_expr(self, meta, children):
        return NotExprNode(operand=children[0], span=_meta_span(meta))

    def valid_from(self, children):
        tok: Token = children[0]
        return ("from", unescape_cacl_string(tok, self._diagnostics), _token_span(tok))

    def valid_until(self, children):
        tok: Token = children[0]
        return ("until", unescape_cacl_string(tok, self._diagnostics), _token_span(tok))

    @v_args(meta=True)
    def time_window(self, meta, children):
        v_from = f_span = v_until = u_span = None
        for kind, value, span in children:
            if kind == "from":
                v_from, f_span = value, span
            else:
                v_until, u_span = value, span
        return TimeWindowNode(
            valid_from=v_from,
            from_span=f_span,
            valid_until=v_until,
            until_span=u_span,
            span=_meta_span(meta),
        )

    @v_args(meta=True)
    def remark_clause(self, meta, children):
        return (
            "remark",
            unescape_cacl_string(children[0], self._diagnostics),
            _meta_span(meta),
        )

    @v_args(meta=True)
    def rule(self, meta, children):
        effect: Effect = children[0]
        op_items, op_set_span = children[1]
        scope = Scope.ALL
        scope_explicit = False
        scope_span: Span | None = None
        match_clause: MatchClauseNode | None = None
        time_window: TimeWindowNode | None = None
        remark: str | None = None
        remark_span: Span | None = None

        for part in children[2:]:
            if isinstance(part, _ScopeSpec):
                scope, scope_explicit, scope_span = part.scope, True, part.span
            elif isinstance(part, _ToList):
                match_clause = MatchClauseNode(
                    syntax="to",
                    expr=self._fold("or", part.items),
                    to_items=part.items,
                    span=part.span,
                )
            elif isinstance(part, TimeWindowNode):
                time_window = part
            elif isinstance(part, tuple) and part[0] == "remark":
                _, remark, remark_span = part
            else:  # bool_expr following `when`
                match_clause = MatchClauseNode(syntax="when", expr=part, span=part.span)

        assert match_clause is not None
        return RuleNode(
            effect=effect,
            op_items=op_items,
            op_set_span=op_set_span,
            scope=scope,
            scope_explicit=scope_explicit,
            scope_span=scope_span,
            match=match_clause,
            time_window=time_window,
            remark=remark,
            remark_span=remark_span,
            span=_meta_span(meta),
        )


_LARK_PARSER = Lark.open(
    "cacl.lark",
    start="start",
    parser="lalr",
    propagate_positions=True,
    rel_to=__file__,
)


def parse_cacl(source: str) -> tuple[PolicyAST | None, list[Diagnostic]]:
    """Parse CACL source text via LALR(1) into a typed AST with diagnostics."""
    diagnostics: list[Diagnostic] = []
    try:
        tree = _LARK_PARSER.parse(source)
    except UnexpectedInput as exc:
        line = getattr(exc, "line", 1) or 1
        col = getattr(exc, "column", 1) or 1
        expected = sorted(getattr(exc, "expected", set()) or set())
        exp_hint = f"Expected one of: {', '.join(expected[:10])}" if expected else None
        diagnostics.append(
            Diagnostic(
                code="E101",
                severity=Severity.ERROR,
                message=f"Syntax error: {exc.__class__.__name__}: {str(exc).splitlines()[0]}",
                span=Span(line, col, line, col + 1),
                hint=exp_hint,
            )
        )
        return None, diagnostics

    ast = _ASTBuilder(diagnostics).transform(tree)
    return ast, diagnostics
