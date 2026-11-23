from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class Span:
    line: int
    column: int
    end_line: int
    end_column: int

    def to_dict(self) -> dict[str, int]:
        return {
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    severity: Severity
    message: str
    span: Span | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.span is not None:
            payload["span"] = self.span.to_dict()
        if self.hint is not None:
            payload["hint"] = self.hint
        return payload


def format_diagnostics(
    diagnostics: list[Diagnostic],
    source: str | None = None,
    filename: str = "<memory>",
) -> str:
    """Render diagnostics in rustc-style annotated format."""
    lines = source.splitlines() if source is not None else []
    rendered: list[str] = []
    for diag in diagnostics:
        header = f"{diag.severity.value}[{diag.code}]: {diag.message}"
        parts = [header]
        if diag.span is not None:
            s = diag.span
            parts.append(f"  --> {filename}:{s.line}:{s.column}")
            if 1 <= s.line <= len(lines):
                src_line = lines[s.line - 1]
                gutter = str(s.line)
                pad = " " * len(gutter)
                caret_start = max(s.column - 1, 0)
                if s.end_line == s.line and s.end_column > s.column:
                    caret_len = s.end_column - s.column
                else:
                    caret_len = max(1, len(src_line) - caret_start)
                parts.append(f"  {pad} |")
                parts.append(f"  {gutter} | {src_line}")
                parts.append(f"  {pad} | {' ' * caret_start}{'^' * caret_len}")
        if diag.hint:
            parts.append(f"  = hint: {diag.hint}")
        rendered.append("\n".join(parts))
    return "\n\n".join(rendered)
