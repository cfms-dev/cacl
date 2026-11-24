from cacl_compiler import Diagnostic as CaclDiagnostic
from cacl_compiler import Severity
from lsprotocol import types

from .analysis import DocumentState

_SEVERITY_MAP: dict[Severity, types.DiagnosticSeverity] = {
    Severity.ERROR: types.DiagnosticSeverity.Error,
    Severity.WARNING: types.DiagnosticSeverity.Warning,
    Severity.INFO: types.DiagnosticSeverity.Information,
}

_UNNECESSARY_CODES: frozenset[str] = frozenset({
    "W201",
    "W202",
    "W206",
    "W207",
    "W208",
    "W211",
    "W212",
})

_DEPRECATED_CODES: frozenset[str] = frozenset({"W209"})


def to_lsp_diagnostic(
    diag: CaclDiagnostic,
    state: DocumentState,
) -> types.Diagnostic:
    if diag.span is not None:
        rng = state.line_index.span_to_range(diag.span)
    else:
        rng = types.Range(
            start=types.Position(line=0, character=0),
            end=types.Position(line=0, character=0),
        )

    message = diag.message
    if diag.hint:
        message = f"{message}\nHint: {diag.hint}"

    tags: list[types.DiagnosticTag] = []
    if diag.code in _UNNECESSARY_CODES:
        tags.append(types.DiagnosticTag.Unnecessary)
    if diag.code in _DEPRECATED_CODES:
        tags.append(types.DiagnosticTag.Deprecated)

    return types.Diagnostic(
        range=rng,
        severity=_SEVERITY_MAP.get(diag.severity, types.DiagnosticSeverity.Error),
        code=diag.code,
        source="cacl",
        message=message,
        tags=tags or None,
        data={"code": diag.code},
    )


def to_lsp_diagnostics(state: DocumentState) -> list[types.Diagnostic]:
    return [to_lsp_diagnostic(diag, state) for diag in state.diagnostics]
