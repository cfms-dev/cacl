from datetime import UTC, datetime

from lsprotocol import types

from cacl_lsp.analysis import ServerSettings, analyze_document
from cacl_lsp.code_actions import get_code_actions
from cacl_lsp.diagnostics import to_lsp_diagnostics
from cacl_lsp.formatting import format_document

NOW = datetime(2026, 11, 24, tzinfo=UTC)


def _apply_edits(source: str, edits: list[types.TextEdit]) -> str:
    from cacl_lsp.coordinates import LineIndex

    idx = LineIndex(source)
    out = source
    # Apply in reverse order
    ordered = sorted(
        edits,
        key=lambda e: (e.range.start.line, e.range.start.character),
        reverse=True,
    )
    for edit in ordered:
        start = idx.position_to_offset(edit.range.start)
        end = idx.position_to_offset(edit.range.end)
        out = out[:start] + edit.new_text + out[end:]
    return out


def test_format_preserves_comments_by_default():
    src = (
        "# Top policy note\n"
        "inherit on;\n"
        "# Rule comment\n"
        'allow [PRESET_READ]   on all   to group("dev");  # inline note\n'
        "# Trailing note\n"
    )
    state = analyze_document("file:///fmt.cacl", src, now_utc=NOW)
    edits = format_document(state, ServerSettings(format_preserve_comments=True))
    assert edits is not None and len(edits) == 1
    result = _apply_edits(src, edits)
    assert "# Top policy note" in result
    assert "# Rule comment" in result
    assert "# inline note" in result
    assert "# Trailing note" in result
    assert "TRAVERSE, LIST_DIRECTORY, READ_CONTENT, READ_METADATA" in result


def test_format_canonical_mode_and_broken_doc_safety():
    src = "# strip me\ninherit on;\nallow [PRESET_READ] to any;\n"
    state = analyze_document("file:///fmt2.cacl", src, now_utc=NOW)
    edits = format_document(
        state,
        ServerSettings(format_preserve_comments=False, format_fold_presets=True),
    )
    assert edits is not None and len(edits) == 1
    result = _apply_edits(src, edits)
    assert "# strip me" not in result
    assert "allow [PRESET_READ] to any;" in result

    # Broken doc must return None
    broken = analyze_document("file:///bad.cacl", "allow [UNKNOWN_OP] to any;", now_utc=NOW)
    assert format_document(broken, ServerSettings()) is None


def test_code_action_quick_fixes():
    # 1. Typo E202 -> suggestion
    src_typo = "allow [READ_CONTNT] to any;\n"
    state_typo = analyze_document("file:///typo.cacl", src_typo, now_utc=NOW)
    diags = to_lsp_diagnostics(state_typo)
    actions = get_code_actions(
        state_typo,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state_typo.uri),
            range=diags[0].range,
            context=types.CodeActionContext(diagnostics=diags),
        ),
    )
    assert any("READ_CONTENT" in a.title for a in actions)

    # 2. `to perm(...)` -> rewrite to `when`
    src_perm = 'allow [TRAVERSE] to group("ops"), perm("audit");\n'
    state_perm = analyze_document("file:///perm.cacl", src_perm, now_utc=NOW)
    diags_perm = to_lsp_diagnostics(state_perm)
    actions_perm = get_code_actions(
        state_perm,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state_perm.uri),
            range=diags_perm[0].range,
            context=types.CodeActionContext(diagnostics=diags_perm),
        ),
    )
    fix = next(a for a in actions_perm if "Convert 'to' clause to 'when'" in a.title)
    rewritten = _apply_edits(src_perm, fix.edit.changes[state_perm.uri])
    assert rewritten == 'allow [TRAVERSE] when group("ops") or perm("audit");\n'

    # 3. Redundant op W202 -> remove with comma
    src_dup = "allow [PRESET_READ, TRAVERSE] to any;\n"
    state_dup = analyze_document("file:///dup.cacl", src_dup, now_utc=NOW)
    diags_dup = to_lsp_diagnostics(state_dup)
    w202 = next(d for d in diags_dup if d.code == "W202")
    actions_dup = get_code_actions(
        state_dup,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state_dup.uri),
            range=w202.range,
            context=types.CodeActionContext(diagnostics=[w202]),
        ),
    )
    rm = next(a for a in actions_dup if "Remove redundant operation" in a.title)
    assert _apply_edits(src_dup, rm.edit.changes[state_dup.uri]) == "allow [PRESET_READ] to any;\n"

    # 4. Duplicate rule W211 -> remove rule
    src_w211 = "allow [TRAVERSE] to any;\nallow [TRAVERSE] to any;\n"
    state_w211 = analyze_document("file:///w211.cacl", src_w211, now_utc=NOW)
    diags_w211 = to_lsp_diagnostics(state_w211)
    w211 = next(d for d in diags_w211 if d.code == "W211")
    actions_w211 = get_code_actions(
        state_w211,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state_w211.uri),
            range=w211.range,
            context=types.CodeActionContext(diagnostics=[w211]),
        ),
    )
    rm_rule = next(a for a in actions_w211 if a.title == "Remove duplicate rule")
    assert (
        _apply_edits(src_w211, rm_rule.edit.changes[state_w211.uri])
        == "allow [TRAVERSE] to any;\n"
    )


def test_code_action_expand_and_fold_refactorings():
    src = "allow [PRESET_ACL_RW] to any;\n"
    state = analyze_document("file:///ref.cacl", src, now_utc=NOW)
    op_range = types.Range(
        start=types.Position(line=0, character=7),
        end=types.Position(line=0, character=15),
    )
    actions = get_code_actions(
        state,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state.uri),
            range=op_range,
            context=types.CodeActionContext(diagnostics=[]),
        ),
    )
    expand = next(a for a in actions if "Expand operation set" in a.title)
    expanded_src = _apply_edits(src, expand.edit.changes[state.uri])
    assert expanded_src == "allow [READ_DACL, WRITE_DACL] to any;\n"

    # Now fold back
    state2 = analyze_document("file:///ref2.cacl", expanded_src, now_utc=NOW)
    actions2 = get_code_actions(
        state2,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=state2.uri),
            range=op_range,
            context=types.CodeActionContext(diagnostics=[]),
        ),
    )
    fold = next(a for a in actions2 if "Fold operation set" in a.title)
    assert _apply_edits(expanded_src, fold.edit.changes[state2.uri]) == src
