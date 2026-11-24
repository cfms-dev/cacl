from datetime import UTC, datetime

from lsprotocol import types

from cacl_lsp.analysis import analyze_document
from cacl_lsp.completion import get_completions
from cacl_lsp.hover import get_hover

NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)


def _labels(src: str, line: int, char: int) -> list[str]:
    state = analyze_document("file:///comp.cacl", src, now_utc=NOW)
    res = get_completions(state, types.Position(line=line, character=char))
    return [item.label for item in res.items]


def test_completion_statement_start_and_inherit():
    labels = _labels("", 0, 0)
    assert "inherit" in labels
    assert "allow" in labels
    assert "deny" in labels

    inherit_vals = _labels("inherit ", 0, 8)
    assert set(inherit_vals) == {"on", "off"}


def test_completion_inside_op_set_and_subtraction():
    op_labels = _labels("allow [", 0, 7)
    assert "PRESET_RW" in op_labels
    assert "READ_CONTENT" in op_labels
    assert len(op_labels) == 28  # 7 macros + 21 atomic ops

    # After `-`, ops present in PRESET_READ should sort before non-present ops
    state = analyze_document("file:///sub.cacl", "allow [PRESET_READ, -", now_utc=NOW)
    res = get_completions(state, types.Position(line=0, character=21))
    by_label = {item.label: item for item in res.items}
    assert by_label["TRAVERSE"].sort_text < by_label["PURGE"].sort_text


def test_completion_scope_to_when_and_timestamp():
    assert set(_labels("allow [TRAVERSE] on ", 0, 20)) == {"self", "dirs", "docs", "all"}

    to_labels = _labels("allow [TRAVERSE] to ", 0, 20)
    assert "user" in to_labels and "group" in to_labels and "any" in to_labels
    assert "perm" not in to_labels

    when_labels = _labels("allow [TRAVERSE] when ", 0, 22)
    assert {"user", "group", "perm", "any", "not"}.issubset(set(when_labels))

    ts_labels = _labels('allow [TRAVERSE] to any from "', 0, 30)
    assert any("2026-11-24T12:00:00Z" in lbl for lbl in ts_labels)

    # Inside comment -> no completions
    assert _labels("# allow ", 0, 8) == []


def test_hover_macro_op_rule_and_timestamp():
    src = (
        "inherit on;\n"
        'allow [PRESET_READ, -TRAVERSE] on docs to user("5a52345a-ae51-4516-b277-bbd94b99d73a") '
        'until "2026-12-01T00:00:00+08:00";\n'
    )
    state = analyze_document("file:///hover.cacl", src, now_utc=NOW)

    # Hover PRESET_READ
    h_macro = get_hover(state, types.Position(line=1, character=9))
    assert h_macro is not None
    assert "Preset Macro `PRESET_READ`" in h_macro.contents.value
    assert "READ_CONTENT" in h_macro.contents.value

    # Hover subtracted -TRAVERSE
    h_sub = get_hover(state, types.Position(line=1, character=23))
    assert h_sub is not None
    assert "-TRAVERSE" in h_sub.contents.value
    assert "Removes this bit" in h_sub.contents.value

    # Hover `allow` includes compiled rule summary
    h_allow = get_hover(state, types.Position(line=1, character=2))
    assert h_allow is not None
    assert "Rule Summary" in h_allow.contents.value
    assert "3 atomic ops" in h_allow.contents.value

    # Hover UUID string
    uuid_col = src.splitlines()[1].index("5a52345a") + 2
    h_uuid = get_hover(state, types.Position(line=1, character=uuid_col))
    assert h_uuid is not None
    assert "Valid 36-char RFC 9562 UUID" in h_uuid.contents.value

    # Hover timestamp string -> shows UTC conversion
    ts_col = src.splitlines()[1].index("2026-12-01") + 2
    h_ts = get_hover(state, types.Position(line=1, character=ts_col))
    assert h_ts is not None
    assert "2026-11-30T16:00:00Z" in h_ts.contents.value
