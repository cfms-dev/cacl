from datetime import UTC, datetime

from lsprotocol import types

from cacl_lsp.analysis import ServerSettings, analyze_document
from cacl_lsp.inlay_hints import get_inlay_hints
from cacl_lsp.semantic_tokens import SEMANTIC_TOKEN_TYPES, get_semantic_tokens
from cacl_lsp.symbols import get_document_symbols, get_folding_ranges

NOW = datetime(2026, 11, 24, tzinfo=UTC)

SAMPLE = """# Header line 1
# Header line 2
inherit on;
allow [PRESET_READ, -TRAVERSE]
  to group("readers")
  until "2026-01-01T00:00:00Z"
  remark "Temporary reader grant";
"""


def test_document_symbols_and_folding_ranges():
    state = analyze_document("file:///nav.cacl", SAMPLE, now_utc=NOW)
    symbols = get_document_symbols(state)
    assert len(symbols) == 2
    assert symbols[0].name == "inherit on"
    assert symbols[0].kind is types.SymbolKind.Property
    assert symbols[1].name == "allow [PRESET_READ, -TRAVERSE] on all"
    assert symbols[1].detail == "Temporary reader grant"

    folds = get_folding_ranges(state)
    kinds = {f.kind for f in folds}
    assert types.FoldingRangeKind.Comment in kinds
    assert types.FoldingRangeKind.Region in kinds


def test_inlay_hints_mask_implicit_scope_and_expired():
    state = analyze_document("file:///hints.cacl", SAMPLE, now_utc=NOW)
    params = types.InlayHintParams(
        text_document=types.TextDocumentIdentifier(uri=state.uri),
        range=state.line_index.full_document_range(),
    )
    hints = get_inlay_hints(state, params, ServerSettings(inlay_hints_enabled=True))
    labels = [h.label for h in hints]
    assert any("(3 ops)" in lbl for lbl in labels)
    assert "on all" in labels
    assert "expired" in labels

    # Disabled setting yields no hints
    assert get_inlay_hints(state, params, ServerSettings(inlay_hints_enabled=False)) == []


def test_semantic_tokens_encoding():
    state = analyze_document("file:///sem.cacl", SAMPLE, now_utc=NOW)
    sem = get_semantic_tokens(state)
    assert len(sem.data) > 0
    assert len(sem.data) % 5 == 0

    # Decode delta tokens and check macro & subtracted enumMember
    decoded: list[tuple[int, int, int, str, int]] = []
    line = 0
    col = 0
    for i in range(0, len(sem.data), 5):
        dl, dc, length, t_idx, mods = sem.data[i : i + 5]
        line += dl
        col = dc if dl > 0 else col + dc
        decoded.append((line, col, length, SEMANTIC_TOKEN_TYPES[t_idx], mods))

    token_types_present = {item[3] for item in decoded}
    assert {"comment", "keyword", "macro", "enumMember", "operator", "function", "string"}.issubset(
        token_types_present
    )
    # TRAVERSE after `-` should have modification bit (bit 1 -> 2)
    traverse_entry = next(item for item in decoded if item[3] == "enumMember")
    assert traverse_entry[4] & (1 << 1)
