from cacl_compiler import decompile_policy, decompile_rule
from cacl_compiler.ast_nodes import PolicyAST
from cacl_compiler.ir import CompiledPolicy
from lsprotocol import types

from .analysis import DocumentState, ServerSettings
from .lexer import TokenKind


def _format_preserving_comments(
    state: DocumentState,
    ast: PolicyAST,
    policy: CompiledPolicy,
    settings: ServerSettings,
) -> str:
    opts = settings.to_decompile_options()
    comments = [tok for tok in state.tokens if tok.kind is TokenKind.COMMENT]
    if not comments:
        return decompile_policy(policy, opts=opts)

    # Identify which lines contain non-comment tokens (for standalone vs inline comment classification)
    code_lines: set[int] = {
        tok.line for tok in state.tokens if tok.kind is not TokenKind.COMMENT
    }

    output_lines: list[str] = []
    comment_idx = 0
    total_comments = len(comments)

    def emit_leading_comments(before_line: int) -> None:
        nonlocal comment_idx
        while comment_idx < total_comments and comments[comment_idx].line < before_line:
            output_lines.append(comments[comment_idx].value)
            comment_idx += 1

    def collect_comments_in_span(start_line: int, end_line: int) -> tuple[list[str], list[str]]:
        """Partition comments within [start_line, end_line] into standalone and inline."""
        nonlocal comment_idx
        standalone: list[str] = []
        inline: list[str] = []
        while comment_idx < total_comments and comments[comment_idx].line <= end_line:
            c = comments[comment_idx]
            comment_idx += 1
            if c.line >= start_line:
                if c.line in code_lines:
                    inline.append(c.value)
                else:
                    standalone.append(c.value)
        return standalone, inline

    def append_inline(stmt: str, inline_comments: list[str]) -> str:
        if not inline_comments:
            return stmt
        merged = " ".join(
            c[1:].strip() if c.startswith("#") else c for c in inline_comments
        )
        return f"{stmt}  # {merged}"

    # 1. Directive section
    emitted_directive = False
    if ast.directives:
        first_dir = ast.directives[0]
        emit_leading_comments(first_dir.span.line)
        standalone, inline = collect_comments_in_span(
            first_dir.span.line, first_dir.span.end_line
        )
        output_lines.extend(standalone)
        if opts.always_emit_inherit or not policy.inherit:
            stmt = f"inherit {'on' if policy.inherit else 'off'};"
            output_lines.append(append_inline(stmt, inline))
            emitted_directive = True
        elif inline:
            output_lines.extend(inline)
    elif opts.always_emit_inherit or not policy.inherit:
        # Place synthesized inherit directive after any file header comment block
        first_rule_line = ast.rules[0].span.line if ast.rules else state.line_index.line_count + 1
        # Emit top-of-file header comments only if separated by blank line or at line 1
        if comments and comments[0].line == 1 and first_rule_line > 1:
            # Consume contiguous leading header comments
            expected_line = 1
            while (
                comment_idx < total_comments
                and comments[comment_idx].line < first_rule_line
                and comments[comment_idx].line == expected_line
                and comments[comment_idx].line not in code_lines
            ):
                output_lines.append(comments[comment_idx].value)
                expected_line += 1
                comment_idx += 1
        output_lines.append(f"inherit {'on' if policy.inherit else 'off'};")
        emitted_directive = True

    if emitted_directive and policy.rules:
        output_lines.append("")

    # 2. Rules section (1:1 alignment between ast.rules and policy.rules when compile succeeded)
    for ast_rule, compiled_rule in zip(ast.rules, policy.rules, strict=True):
        emit_leading_comments(ast_rule.span.line)
        standalone, inline = collect_comments_in_span(
            ast_rule.span.line, ast_rule.span.end_line
        )
        output_lines.extend(standalone)
        formatted_rule = decompile_rule(compiled_rule, opts=opts)
        output_lines.append(append_inline(formatted_rule, inline))

    # 3. Trailing comments at end of file
    while comment_idx < total_comments:
        output_lines.append(comments[comment_idx].value)
        comment_idx += 1

    if not output_lines:
        return ""
    return "\n".join(output_lines) + "\n"


def format_document(
    state: DocumentState,
    settings: ServerSettings,
) -> list[types.TextEdit] | None:
    """Format a valid CACL document; returns None if the document has compile errors."""
    if (
        state.ast is None
        or state.compile_result is None
        or not state.compile_result.ok
        or state.compile_result.policy is None
    ):
        return None

    policy = state.compile_result.policy
    if settings.format_preserve_comments:
        formatted = _format_preserving_comments(state, state.ast, policy, settings)
    else:
        formatted = decompile_policy(policy, opts=settings.to_decompile_options())

    if formatted == state.source:
        return []

    return [
        types.TextEdit(
            range=state.line_index.full_document_range(),
            new_text=formatted,
        )
    ]
