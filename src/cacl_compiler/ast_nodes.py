from dataclasses import dataclass
from enum import Enum

from .diagnostics import Span


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Scope(str, Enum):
    SELF = "self"
    DIRS = "dirs"
    DOCS = "docs"
    ALL = "all"


class PredicateKind(str, Enum):
    USER = "user"
    GROUP = "group"
    PERM = "perm"
    ROLE = "role"  # Optional extension (disabled by default in strict CEP-0002 mode)


@dataclass(frozen=True, slots=True)
class OpItemNode:
    name: str
    subtract: bool
    span: Span


@dataclass(frozen=True, slots=True)
class InheritDirectiveNode:
    enabled: bool
    span: Span


# --- Condition AST ---


class ExprNode:
    span: Span


@dataclass(frozen=True, slots=True)
class AnyExprNode(ExprNode):
    span: Span


@dataclass(frozen=True, slots=True)
class PredicateExprNode(ExprNode):
    kind: PredicateKind
    raw_value: str
    span: Span


@dataclass(frozen=True, slots=True)
class NotExprNode(ExprNode):
    operand: ExprNode
    span: Span


@dataclass(frozen=True, slots=True)
class BinaryExprNode(ExprNode):
    op: str  # "and" | "or"
    left: ExprNode
    right: ExprNode
    span: Span


@dataclass(frozen=True, slots=True)
class MatchClauseNode:
    syntax: str  # "to" | "when"
    expr: ExprNode
    # Preserves raw principal list for duplicate-principal warnings on `to` clauses
    to_items: tuple[ExprNode, ...] = ()
    span: Span | None = None


@dataclass(frozen=True, slots=True)
class TimeWindowNode:
    valid_from: str | None
    from_span: Span | None
    valid_until: str | None
    until_span: Span | None
    span: Span


@dataclass(frozen=True, slots=True)
class RuleNode:
    effect: Effect
    op_items: tuple[OpItemNode, ...]
    op_set_span: Span
    scope: Scope
    scope_explicit: bool
    scope_span: Span | None
    match: MatchClauseNode
    time_window: TimeWindowNode | None
    remark: str | None
    remark_span: Span | None
    span: Span


@dataclass(frozen=True, slots=True)
class PolicyAST:
    directives: tuple[InheritDirectiveNode, ...]
    rules: tuple[RuleNode, ...]
