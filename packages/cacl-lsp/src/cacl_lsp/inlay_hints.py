from cacl_compiler import DEFAULT_PRESET_MACROS
from cacl_compiler.analyzer import _parse_rfc3339_utc
from cacl_compiler.permissions import mask_to_atomic_names
from lsprotocol import types

from .analysis import DocumentState, ServerSettings, evaluate_rule_op_mask


def _position_in_range(pos: types.Position, rng: types.Range) -> bool:
    p = (pos.line, pos.character)
    s = (rng.start.line, rng.start.character)
    e = (rng.end.line, rng.end.character)
    return s <= p <= e


def get_inlay_hints(
    state: DocumentState,
    params: types.InlayHintParams,
    settings: ServerSettings,
) -> list[types.InlayHint]:
    if not settings.inlay_hints_enabled or state.ast is None:
        return []

    hints: list[types.InlayHint] = []
    req_range = params.range

    for rule in state.ast.rules:
        op_end_pos = state.line_index.span_to_position_end(rule.op_set_span)

        # 1. Resolved bitmask & op count hint when macros or subtractions are used
        uses_macro_or_sub = any(
            item.subtract or item.name in DEFAULT_PRESET_MACROS
            for item in rule.op_items
        )
        if uses_macro_or_sub and _position_in_range(op_end_pos, req_range):
            mask, all_valid = evaluate_rule_op_mask(rule)
            if all_valid and mask > 0:
                ops = mask_to_atomic_names(mask)
                hints.append(
                    types.InlayHint(
                        position=op_end_pos,
                        label=f" = 0x{mask:06x} ({len(ops)} ops)",
                        kind=types.InlayHintKind.Type,
                        tooltip=types.MarkupContent(
                            kind=types.MarkupKind.Markdown,
                            value=(
                                "**Resolved atomic operations:**\n\n"
                                + ", ".join(f"`{name}`" for name in ops)
                            ),
                        ),
                        padding_left=False,
                        padding_right=True,
                    )
                )

        # 2. Implicit default scope (`on all`) hint
        if not rule.scope_explicit and _position_in_range(op_end_pos, req_range):
            hints.append(
                types.InlayHint(
                    position=op_end_pos,
                    label="on all",
                    kind=types.InlayHintKind.Parameter,
                    tooltip="Implicit default scope (CEP 2: omitted `on` defaults to `on all`)",
                    padding_left=True,
                    padding_right=True,
                )
            )

        # 3. Expired `until` timestamp hint
        if (
            rule.time_window is not None
            and rule.time_window.valid_until is not None
            and rule.time_window.until_span is not None
        ):
            parsed_until = _parse_rfc3339_utc(rule.time_window.valid_until)
            if parsed_until is not None and parsed_until <= state.now_utc:
                until_end = state.line_index.span_to_position_end(
                    rule.time_window.until_span
                )
                if _position_in_range(until_end, req_range):
                    hints.append(
                        types.InlayHint(
                            position=until_end,
                            label="expired",
                            kind=types.InlayHintKind.Type,
                            tooltip="Rule time window has already expired relative to UTC clock",
                            padding_left=True,
                            padding_right=False,
                        )
                    )

    return hints
