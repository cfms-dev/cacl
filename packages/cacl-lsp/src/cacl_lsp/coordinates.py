from bisect import bisect_right

from cacl_compiler import Span
from lsprotocol import types


def utf16_len(text: str) -> int:
    """Return the length of *text* measured in UTF-16 code units."""
    if text.isascii():
        return len(text)
    return len(text.encode("utf-16-le")) // 2


def codepoint_col_to_utf16(line_text: str, col_0based: int) -> int:
    """Convert a 0-based Python codepoint index in *line_text* to UTF-16 units."""
    clamped = max(0, min(col_0based, len(line_text)))
    if clamped == 0:
        return 0
    prefix = line_text[:clamped]
    return utf16_len(prefix)


def utf16_col_to_codepoint(line_text: str, utf16_col: int) -> int:
    """Convert a 0-based UTF-16 code unit offset in *line_text* to a codepoint index."""
    if utf16_col <= 0:
        return 0
    if line_text.isascii():
        return min(utf16_col, len(line_text))
    units = 0
    for idx, ch in enumerate(line_text):
        if units >= utf16_col:
            return idx
        units += 2 if ord(ch) > 0xFFFF else 1
    return len(line_text)


class LineIndex:
    """Bidirectional mapping between raw character offsets, 1-based Spans, and LSP UTF-16 positions."""

    __slots__ = ("source", "lines", "line_starts")

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines: list[str] = []
        self.line_starts: list[int] = [0]

        pos = 0
        length = len(source)
        while pos < length:
            nl = source.find("\n", pos)
            if nl == -1:
                line = source[pos:]
                if line.endswith("\r"):
                    line = line[:-1]
                self.lines.append(line)
                break
            line = source[pos:nl]
            if line.endswith("\r"):
                line = line[:-1]
            self.lines.append(line)
            pos = nl + 1
            self.line_starts.append(pos)

        if not self.lines:
            self.lines.append("")
        elif source.endswith("\n"):
            self.lines.append("")

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def line_text(self, line_0based: int) -> str:
        if 0 <= line_0based < len(self.lines):
            return self.lines[line_0based]
        return ""

    def offset_to_position(self, offset: int) -> types.Position:
        clamped = max(0, min(offset, len(self.source)))
        line_idx = bisect_right(self.line_starts, clamped) - 1
        line_idx = max(0, min(line_idx, len(self.lines) - 1))
        col_cp = clamped - self.line_starts[line_idx]
        return types.Position(
            line=line_idx,
            character=codepoint_col_to_utf16(self.lines[line_idx], col_cp),
        )

    def position_to_offset(self, position: types.Position) -> int:
        if position.line < 0:
            return 0
        if position.line >= len(self.lines):
            return len(self.source)
        line_str = self.lines[position.line]
        col_cp = utf16_col_to_codepoint(line_str, position.character)
        return self.line_starts[position.line] + col_cp

    def span_to_position_start(self, span: Span) -> types.Position:
        return self._one_based_to_position(span.line, span.column)

    def span_to_position_end(self, span: Span) -> types.Position:
        return self._one_based_to_position(span.end_line, span.end_column)

    def span_to_range(self, span: Span) -> types.Range:
        start = self._one_based_to_position(span.line, span.column)
        end = self._one_based_to_position(span.end_line, span.end_column)
        if (end.line, end.character) < (start.line, start.character):
            end = start
        return types.Range(start=start, end=end)

    def span_to_offsets(self, span: Span) -> tuple[int, int]:
        start_pos = self.span_to_position_start(span)
        end_pos = self.span_to_position_end(span)
        return self.position_to_offset(start_pos), self.position_to_offset(end_pos)

    def full_document_range(self) -> types.Range:
        last_line = len(self.lines) - 1
        end_char = utf16_len(self.lines[last_line])
        return types.Range(
            start=types.Position(line=0, character=0),
            end=types.Position(line=last_line, character=end_char),
        )

    def contains_position(self, span: Span, position: types.Position) -> bool:
        rng = self.span_to_range(span)
        pos_key = (position.line, position.character)
        start_key = (rng.start.line, rng.start.character)
        end_key = (rng.end.line, rng.end.character)
        return start_key <= pos_key <= end_key

    def _one_based_to_position(self, line_1: int, col_1: int) -> types.Position:
        if not self.lines:
            return types.Position(line=0, character=0)
        line_0 = max(0, min(line_1 - 1, len(self.lines) - 1))
        line_str = self.lines[line_0]
        if line_1 - 1 >= len(self.lines):
            # Clamped from past EOF: point to end of last line
            return types.Position(line=line_0, character=utf16_len(line_str))
        col_0 = max(0, col_1 - 1)
        return types.Position(
            line=line_0,
            character=codepoint_col_to_utf16(line_str, col_0),
        )
