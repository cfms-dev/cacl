from cacl_compiler import Span
from lsprotocol import types

from cacl_lsp.coordinates import LineIndex, codepoint_col_to_utf16, utf16_col_to_codepoint
from cacl_lsp.lexer import TokenKind, token_at_offset, tokenize_cacl


def test_utf16_conversion_with_surrogate_pair():
    # 😀 is 1 Python codepoint (U+1F600) = 2 UTF-16 code units
    line = '# 😀 hi'
    assert codepoint_col_to_utf16(line, 0) == 0
    assert codepoint_col_to_utf16(line, 2) == 2
    assert codepoint_col_to_utf16(line, 3) == 4  # after 😀
    assert codepoint_col_to_utf16(line, 6) == 7
    assert utf16_col_to_codepoint(line, 4) == 3
    assert utf16_col_to_codepoint(line, 7) == 6


def test_line_index_span_and_eof_clamping():
    src = 'inherit on;\nallow [TRAVERSE] to any;\n'
    idx = LineIndex(src)
    rng = idx.span_to_range(Span(2, 8, 2, 16))
    assert rng == types.Range(
        start=types.Position(line=1, character=7),
        end=types.Position(line=1, character=15),
    )

    # Past-EOF span should clamp safely instead of raising
    clamped = idx.span_to_range(Span(99, 5, 99, 10))
    assert clamped.start.line == idx.line_count - 1


def test_lexer_handles_valid_and_broken_input():
    src = '# 注释 😀\nallow [PRESET_RW, -DELETE] on docs when perm("audit") and "unterminated'
    tokens = tokenize_cacl(src)
    kinds = [t.kind for t in tokens]
    assert kinds[0] is TokenKind.COMMENT
    assert TokenKind.IDENT in kinds
    assert TokenKind.MINUS in kinds
    assert TokenKind.PREDICATE in kinds
    assert tokens[-1].kind is TokenKind.STRING
    assert tokens[-1].terminated is False

    # token_at_offset locates PRESET_RW
    preset_tok = next(t for t in tokens if t.value == "PRESET_RW")
    assert token_at_offset(tokens, preset_tok.start_offset + 2) is preset_tok
