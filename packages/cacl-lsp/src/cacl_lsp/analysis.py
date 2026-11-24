from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cacl_compiler import (
    ATOMIC_OP_BY_NAME,
    DEFAULT_PRESET_MACROS,
    CompilerConfig,
    CompileResult,
    DecompileOptions,
    Diagnostic,
    ObjectType,
    compile_ast,
    parse_cacl,
)
from cacl_compiler.ast_nodes import PolicyAST, RuleNode

from .coordinates import LineIndex
from .lexer import LexToken, tokenize_cacl


@dataclass(frozen=True, slots=True)
class ServerSettings:
    target_object_type: ObjectType | None = None
    format_preserve_comments: bool = True
    format_fold_presets: bool = False
    format_prefer_to_syntax: bool = True
    format_omit_default_scope: bool = True
    format_always_emit_inherit: bool = True
    inlay_hints_enabled: bool = True

    @classmethod
    def from_vscode_config(cls, raw: Mapping[str, Any] | None) -> ServerSettings:
        if not isinstance(raw, Mapping):
            return cls()

        compiler_cfg = raw.get("compiler")
        if not isinstance(compiler_cfg, Mapping):
            compiler_cfg = {}

        fmt_cfg = raw.get("format")
        if not isinstance(fmt_cfg, Mapping):
            fmt_cfg = {}

        inlay_cfg = raw.get("inlayHints")
        if not isinstance(inlay_cfg, Mapping):
            inlay_cfg = {}

        target_raw = compiler_cfg.get("targetObjectType")
        target_type: ObjectType | None = None
        if target_raw in ("directory", "document"):
            target_type = ObjectType(target_raw)

        return cls(
            target_object_type=target_type,
            format_preserve_comments=bool(fmt_cfg.get("preserveComments", True)),
            format_fold_presets=bool(fmt_cfg.get("foldPresets", False)),
            format_prefer_to_syntax=bool(fmt_cfg.get("preferToSyntax", True)),
            format_omit_default_scope=bool(fmt_cfg.get("omitDefaultScope", True)),
            format_always_emit_inherit=bool(fmt_cfg.get("alwaysEmitInherit", True)),
            inlay_hints_enabled=bool(inlay_cfg.get("enabled", True)),
        )

    def to_compiler_config(self, now_utc: datetime | None = None) -> CompilerConfig:
        return CompilerConfig(
            target_object_type=self.target_object_type,
            now_utc=now_utc,
        )

    def to_decompile_options(self) -> DecompileOptions:
        return DecompileOptions(
            fold_presets=self.format_fold_presets,
            prefer_to_syntax=self.format_prefer_to_syntax,
            omit_default_scope=self.format_omit_default_scope,
            always_emit_inherit=self.format_always_emit_inherit,
        )


@dataclass(frozen=True, slots=True)
class DocumentState:
    uri: str
    version: int | None
    source: str
    line_index: LineIndex
    tokens: tuple[LexToken, ...]
    ast: PolicyAST | None
    compile_result: CompileResult | None
    diagnostics: tuple[Diagnostic, ...]
    now_utc: datetime


def evaluate_rule_op_mask(
    rule: RuleNode,
    macros: Mapping[str, int] | None = None,
) -> tuple[int, bool]:
    """Compute effective bitmask for *rule.op_items* and whether all items were valid."""
    macro_table = DEFAULT_PRESET_MACROS if macros is None else macros
    mask = 0
    all_valid = True
    for idx, item in enumerate(rule.op_items):
        meta = ATOMIC_OP_BY_NAME.get(item.name)
        if meta is not None:
            item_mask = int(meta.op)
        elif item.name in macro_table:
            item_mask = macro_table[item.name]
        else:
            all_valid = False
            continue
        if item.subtract:
            if idx == 0:
                all_valid = False
                continue
            mask &= ~item_mask
        else:
            mask |= item_mask
    return mask, all_valid


def analyze_document(
    uri: str,
    source: str,
    version: int | None = None,
    settings: ServerSettings | None = None,
    now_utc: datetime | None = None,
) -> DocumentState:
    """Parse, lex, and semantically analyze a CACL document for LSP features."""
    cfg_settings = settings or ServerSettings()
    clock = (now_utc or datetime.now(UTC)).astimezone(UTC)
    line_index = LineIndex(source)
    tokens = tokenize_cacl(source)

    ast, parse_diags = parse_cacl(source)
    compile_result: CompileResult | None = None
    all_diags: list[Diagnostic] = list(parse_diags)

    if ast is not None:
        compile_result = compile_ast(
            ast,
            config=cfg_settings.to_compiler_config(now_utc=clock),
        )
        all_diags.extend(compile_result.diagnostics)
        # If parse had errors (e.g. E102 invalid escape), policy must not be treated as valid
        if any(d.severity.value == "error" for d in parse_diags):
            compile_result = CompileResult(
                policy=None,
                diagnostics=all_diags,
            )

    return DocumentState(
        uri=uri,
        version=version,
        source=source,
        line_index=line_index,
        tokens=tokens,
        ast=ast,
        compile_result=compile_result,
        diagnostics=tuple(all_diags),
        now_utc=clock,
    )
