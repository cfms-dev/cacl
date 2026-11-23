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

    @v_args(meta=True)
    def inherit_stmt(self, meta, children):
        mode_tok: Token = children[1]
        return InheritDirectiveNode(
            enabled=(mode_tok.value == "on"), span=_meta_span(meta)
        )

    @v_args(meta=True)
    def op_item(self, meta, children):
        if len(children) == 2:
            sign_tok, ident_tok = children
            subtract = sign_tok.value == "-"
        else:
            ident_tok = children[0]
            subtract = False
        return OpItemNode(
            name=ident_tok.value, subtract=subtract, span=_meta_span(meta)
        )

    @v_args(meta=True)
    def op_set(self, meta, children):
        return (tuple(children), _meta_span(meta))

    @v_args(meta=True)
    def scope_clause(self, meta, children):
        scope_tok: Token = children[1]
        return ("scope", Scope(scope_tok.value), _meta_span(meta))

    def principal_kind(self, children):
        return PredicateKind(children[0].value)

    def pred_kind(self, children):
        return PredicateKind(children[0].value)

    @v_args(meta=True)
    def pred_any(self, meta, children):
        return AnyExprNode(span=_meta_span(meta))

    @v_args(meta=True)
    def pred_atom(self, meta, children):
        kind: PredicateKind = children[0]
        str_tok: Token = children[1]
        val = unescape_cacl_string(str_tok, self._diagnostics)
        return PredicateExprNode(kind=kind, raw_value=val, span=_meta_span(meta))

    def principal_list(self, children):
        return tuple(children)

    @v_args(meta=True)
    def to_clause(self, meta, children):
        items: tuple[ExprNode, ...] = children[1]
        expr: ExprNode = items[0]
        for nxt in items[1:]:
            expr = BinaryExprNode(
                op="or",
                left=expr,
                right=nxt,
                span=Span(
                    expr.span.line,
                    expr.span.column,
                    nxt.span.end_line,
                    nxt.span.end_column,
                ),
            )
        return MatchClauseNode(
            syntax="to", expr=expr, to_items=items, span=_meta_span(meta)
        )

    @v_args(meta=True)
    def when_clause(self, meta, children):
        return MatchClauseNode(syntax="when", expr=children[1], span=_meta_span(meta))

    @v_args(meta=True)
    def bool_or(self, meta, children):
        return BinaryExprNode(
            op="or", left=children[0], right=children[2], span=_meta_span(meta)
        )

    @v_args(meta=True)
    def bool_and(self, meta, children):
        return BinaryExprNode(
            op="and", left=children[0], right=children[2], span=_meta_span(meta)
        )

    @v_args(meta=True)
    def bool_not(self, meta, children):
        return NotExprNode(operand=children[1], span=_meta_span(meta))

    @v_args(meta=True)
    def from_clause(self, meta, children):
        tok: Token = children[1]
        return (unescape_cacl_string(tok, self._diagnostics), _token_span(tok))

    @v_args(meta=True)
    def until_clause(self, meta, children):
        tok: Token = children[1]
        return (unescape_cacl_string(tok, self._diagnostics), _token_span(tok))

    @v_args(meta=True)
    def time_from_opt_until(self, meta, children):
        v_from, f_span = children[0]
        if len(children) == 2:
            v_until, u_span = children[1]
        else:
            v_until, u_span = None, None
        return TimeWindowNode(
            valid_from=v_from,
            from_span=f_span,
            valid_until=v_until,
            until_span=u_span,
            span=_meta_span(meta),
        )

    @v_args(meta=True)
    def time_only_until(self, meta, children):
        v_until, u_span = children[0]
        return TimeWindowNode(
            valid_from=None,
            from_span=None,
            valid_until=v_until,
            until_span=u_span,
            span=_meta_span(meta),
        )

    @v_args(meta=True)
    def remark_clause(self, meta, children):
        tok: Token = children[1]
        return (
            "remark",
            unescape_cacl_string(tok, self._diagnostics),
            _meta_span(meta),
        )

    @v_args(meta=True)
    def rule_stmt(self, meta, children):
        effect = Effect(children[0].value)
        op_items, op_set_span = children[1]
        scope = Scope.ALL
        scope_explicit = False
        scope_span: Span | None = None
        match_clause: MatchClauseNode | None = None
        time_window: TimeWindowNode | None = None
        remark: str | None = None
        remark_span: Span | None = None

        for part in children[2:]:
            if isinstance(part, tuple) and part[0] == "scope":
                _, scope, scope_span = part
                scope_explicit = True
            elif isinstance(part, MatchClauseNode):
                match_clause = part
            elif isinstance(part, TimeWindowNode):
                time_window = part
            elif isinstance(part, tuple) and part[0] == "remark":
                _, remark, remark_span = part

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
