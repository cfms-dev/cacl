# cacl-compiler

Standalone parser, static analyzer, DNF compiler, canonical decompiler/formatter, and CLI (`caclc`) for **CFMS Access Control Language (CACL)**, implemented in accordance with [CEP 2](https://ceps.readthedocs.io/en/latest/cep-0002).

## Features

- **LALR(1) Parser**: Parses `.cacl` policies (`cacl.lark`) with full source spans and strict string-escape validation (`\"`, `\\`, `\n`, `\r`, `\t`).
- **Permission Algebra & Macros**: Supports all 21 CEP 2 atomic operations (`AtomicOp`, bits `0..20`) and 7 preset macros (`CREATE_CHILD`, `MOVE`, `PRESET_READ`, `PRESET_WRITE`, `PRESET_RW`, `PRESET_TRASH_RW`, `PRESET_ACL_RW`), including subtractive syntax (`-OP`).
- **Static Analysis & Diagnostics**: Checks duplicate `inherit` directives, unknown/empty/redundant operations, `perm(...)` in `to` clauses, strict 36-character RFC 9562 UUID validation for `user(...)`, RFC 3339 half-open time windows `[from, until)`, dead/tautological/absorbed conditions, scope-operation applicability, duplicate rules, and `deny ... on all to any` shadowing.
- **Canonical DNF Lowering & IR**: Compiles boolean `when` / `to` expressions into canonical Disjunctive Normal Form (`CompiledPolicy` / `CompiledRule` / `DNFClause` / `ConditionAtom`) with deterministic SHA-256 policy fingerprinting (`CompiledPolicy.fingerprint()`).
- **Lossless Decompiler & Formatter**: Decompiles JSON IR back into canonical `.cacl` syntax (`decompile_policy`, `format_cacl`), with optional preset macro folding and `to` shorthand rendering.

## Requirements

- Python `>= 3.15`
- `lark >= 1.3.1`

## Installation

From the monorepo root with `uv`:

```bash
uv sync
```

Or install the package directly into an environment:

```bash
pip install ./packages/cacl-compiler
```

## CLI Usage (`caclc`)

### Validate a policy (`check`)

```bash
caclc check policy.cacl
caclc check policy.cacl --json --target-type directory
cat policy.cacl | caclc check -
```

### Compile to JSON IR (`compile`)

```bash
caclc compile policy.cacl -o policy.ir.json
caclc compile policy.cacl --diag-json --target-type document
```

### Decompile JSON IR back to CACL (`decompile`)

```bash
caclc decompile policy.ir.json -o policy.cacl
caclc decompile policy.ir.json --fold-presets --always-when
```

### Format & canonicalize (`fmt`)

```bash
caclc fmt policy.cacl
caclc fmt policy.cacl -w --fold-presets
```

## Python API

```python
from cacl_compiler import (
    CompilerConfig,
    DecompileOptions,
    ObjectType,
    compile_cacl,
    decompile_policy,
    format_diagnostics,
)

source = """
inherit on;
allow [PRESET_RW, -DELETE] on docs to group("editors");
"""

result = compile_cacl(
    source,
    config=CompilerConfig(target_object_type=ObjectType.DIRECTORY),
)
if not result.ok:
    print(format_diagnostics(result.diagnostics, source=source, filename="policy.cacl"))
else:
    assert result.policy is not None
    print("Fingerprint:", result.policy.fingerprint())
    print("IR:", result.policy.to_dict())
    print("Formatted:\n" + decompile_policy(result.policy, DecompileOptions(fold_presets=True)))
```

Main exported symbols (`cacl_compiler`):

- **Compilation & AST**: `parse_cacl`, `compile_ast`, `compile_cacl`, `CompilerConfig`, `CompileResult`, `collect_principal_refs`, `PrincipalRef`, `parse_canonical_uuid`
- **IR & Enums**: `CompiledPolicy`, `CompiledRule`, `DNFClause`, `ConditionAtom`, `Effect`, `Scope`, `PredicateKind`, `ObjectType`, `AtomicOp`, `ATOMIC_OP_BY_NAME`, `ATOMIC_OP_BY_FLAG`, `DEFAULT_PRESET_MACROS`
- **Decompilation & Diagnostics**: `decompile_policy`, `decompile_rule`, `DecompileOptions`, `format_cacl`, `Diagnostic`, `Severity`, `Span`, `format_diagnostics`

## Diagnostics Summary

- **Syntax (`E1xx`)**: `E101` syntax error, `E102` invalid/unterminated string escape.
- **Semantic & Validation (`E2xx`, `E302`)**: `E201` duplicate `inherit`, `E202` unknown operation/macro, `E203` empty effective bitmask, `E204` empty predicate argument, `E205` `perm(...)` inside `to`, `E206` invalid RFC 3339 timestamp, `E207` inverted/empty `[from, until)` window, `E208` DNF clause limit exceeded, `E210` leading negative operation item, `E302` non-UUID `user(...)` identifier.
- **Static Warnings (`W2xx`)**: `W201` subtracting absent bits, `W202` redundant operation, `W203`/`W204`/`W205` scope applicability mismatches, `W206` dead/unsatisfiable condition, `W207` `any` absorbing disjunction branches, `W208` duplicate principal in `to`, `W209` expired rule relative to UTC clock, `W210` temporary `deny` with `until`, `W211` duplicate rule, `W212` `allow` shadowed by unconditional `deny ... on all to any`, `W213` tautological condition.

## Testing

```bash
uv run pytest packages/cacl-compiler/tests
```

## License

Licensed under the [MIT License](./LICENSE).
