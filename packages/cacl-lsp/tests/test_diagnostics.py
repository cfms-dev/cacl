from datetime import UTC, datetime

from cacl_compiler import ObjectType
from lsprotocol import types

from cacl_lsp.analysis import ServerSettings, analyze_document
from cacl_lsp.diagnostics import to_lsp_diagnostics

NOW = datetime(2026, 11, 24, tzinfo=UTC)


def test_diagnostics_include_codes_hints_and_tags():
    src = (
        "inherit on;\n"
        'allow [PRESET_READ, TRAVERSE] on dirs to user("not-a-uuid") '
        'until "2026-01-01T00:00:00Z";\n'
    )
    state = analyze_document("file:///test.cacl", src, version=1, now_utc=NOW)
    lsp_diags = to_lsp_diagnostics(state)
    by_code = {d.code: d for d in lsp_diags}

    assert "W202" in by_code
    assert by_code["W202"].severity is types.DiagnosticSeverity.Warning
    assert types.DiagnosticTag.Unnecessary in (by_code["W202"].tags or [])

    assert "E302" in by_code
    assert by_code["E302"].severity is types.DiagnosticSeverity.Error
    assert "Hint:" in by_code["E302"].message

    assert "W209" in by_code
    assert types.DiagnosticTag.Deprecated in (by_code["W209"].tags or [])


def test_scope_span_is_precisely_targeted():
    src = "allow [READ_CONTENT] on dirs to any;\n"
    state = analyze_document("file:///scope.cacl", src, version=1, now_utc=NOW)
    assert state.ast is not None
    assert state.ast.rules[0].scope_span is not None

    lsp_diags = to_lsp_diagnostics(state)
    w204 = next(d for d in lsp_diags if d.code == "W204")
    # `dirs` starts at column 24 (0-based) on line 0
    assert w204.range.start == types.Position(line=0, character=24)
    assert w204.range.end == types.Position(line=0, character=28)


def test_target_object_type_setting_enables_w205():
    src = "allow [TRAVERSE] on self to any;\n"
    settings = ServerSettings(target_object_type=ObjectType.DOCUMENT)
    state = analyze_document(
        "file:///doc.cacl", src, version=1, settings=settings, now_utc=NOW
    )
    codes = {d.code for d in to_lsp_diagnostics(state)}
    assert "W205" in codes


def test_syntax_error_produces_e101_without_crashing():
    src = "allow [TRAVERSE] to"
    state = analyze_document("file:///broken.cacl", src, version=1, now_utc=NOW)
    lsp_diags = to_lsp_diagnostics(state)
    assert any(d.code == "E101" for d in lsp_diags)
