from lsprotocol import types

from .analysis import DocumentState
from .lexer import TokenKind


def get_document_symbols(state: DocumentState) -> list[types.DocumentSymbol]:
    if state.ast is None:
        return []

    symbols: list[types.DocumentSymbol] = []

    for directive in state.ast.directives:
        rng = state.line_index.span_to_range(directive.span)
        symbols.append(
            types.DocumentSymbol(
                name=f"inherit {'on' if directive.enabled else 'off'}",
                detail="directive",
                kind=types.SymbolKind.Property,
                range=rng,
                selection_range=rng,
            )
        )

    for idx, rule in enumerate(state.ast.rules, start=1):
        ops_raw = ", ".join(
            f"-{item.name}" if item.subtract else item.name for item in rule.op_items
        )
        if len(ops_raw) > 40:
            ops_raw = ops_raw[:37] + "..."
        name = f"{rule.effect.value} [{ops_raw}] on {rule.scope.value}"
        detail = rule.remark if rule.remark is not None else f"rule #{idx} ({rule.match.syntax})"
        full_rng = state.line_index.span_to_range(rule.span)
        sel_rng = state.line_index.span_to_range(rule.op_set_span)

        symbols.append(
            types.DocumentSymbol(
                name=name,
                detail=detail,
                kind=types.SymbolKind.Key,
                range=full_rng,
                selection_range=sel_rng,
            )
        )

    return symbols


def get_folding_ranges(state: DocumentState) -> list[types.FoldingRange]:
    ranges: list[types.FoldingRange] = []

    # 1. Multi-line rules from AST
    if state.ast is not None:
        for rule in state.ast.rules:
            start_line = max(0, rule.span.line - 1)
            end_line = max(0, rule.span.end_line - 1)
            if end_line > start_line:
                ranges.append(
                    types.FoldingRange(
                        start_line=start_line,
                        end_line=end_line,
                        kind=types.FoldingRangeKind.Region,
                    )
                )

    # 2. Consecutive comment-only line blocks (2+ lines)
    code_lines: set[int] = {
        tok.line for tok in state.tokens if tok.kind is not TokenKind.COMMENT
    }
    comment_only_lines = sorted({
        tok.line
        for tok in state.tokens
        if tok.kind is TokenKind.COMMENT and tok.line not in code_lines
    })

    block_start: int | None = None
    prev_line: int | None = None
    for line_1 in comment_only_lines:
        if block_start is None:
            block_start = line_1
            prev_line = line_1
        elif prev_line is not None and line_1 == prev_line + 1:
            prev_line = line_1
        else:
            if prev_line is not None and prev_line > block_start:
                ranges.append(
                    types.FoldingRange(
                        start_line=block_start - 1,
                        end_line=prev_line - 1,
                        kind=types.FoldingRangeKind.Comment,
                    )
                )
            block_start = line_1
            prev_line = line_1

    if block_start is not None and prev_line is not None and prev_line > block_start:
        ranges.append(
            types.FoldingRange(
                start_line=block_start - 1,
                end_line=prev_line - 1,
                kind=types.FoldingRangeKind.Comment,
            )
        )

    return ranges
