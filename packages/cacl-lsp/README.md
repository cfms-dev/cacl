# cacl-lsp

Language Server Protocol (LSP) server for **CFMS Access Control Language (CACL / CEP 2)**, built on top of [`cacl-compiler`](../cacl-compiler/README.md) and `pygls`.

## Features

- **Real-Time Diagnostics**: Publishes `cacl-compiler` syntax and semantic errors/warnings (`E1xx`, `E2xx`, `E302`, `W2xx`) on document open, change, save, and configuration updates.
- **Context-Aware Auto-Completion**: Suggests top-level keywords (`inherit`, `allow`, `deny`), atomic operations and preset macros inside `[...]`, scopes (`self`, `dirs`, `docs`, `all`), predicates (`user`, `group`, `perm`, `any`), boolean operators (`and`, `or`, `not`), temporal keywords (`from`, `until`, `remark`), and RFC 3339 UTC timestamp snippets.
- **Hover Documentation**: Displays Markdown documentation for atomic operations (bit offset, hex mask, target/state applicability), preset macros (resolved mask and expanded operations), scopes, predicates, and keywords.
- **Semantic Tokens**: Full semantic token highlighting distinguishing keywords, logical/subtraction operators, preset macros, atomic operations, scopes, predicates, strings, comments, and parameters.
- **Document Formatting**: Comment-preserving formatting (`textDocument/formatting`) supporting leading, inline, and trailing `#` comments as well as configurable preset folding, `to` shorthand, default `on all` omission, and `inherit` emission.
- **Code Actions**:
  - Quick fixes for duplicate `inherit` directives, duplicate principals in `to`, duplicate rules, redundant operation bits, and fuzzy typo replacement for unknown operations (`E202`).
  - Refactoring rewrites to convert between `to ...` and `when ...`, expand operation sets to atomic operations, or fold operation sets using preset macros.
- **Inlay Hints**: Shows resolved hex bitmasks and operation counts (`= 0x... (N ops)`) for rules using macros/subtractions, implicit `on all` scopes, and `expired` badges on past `until` timestamps.
- **Navigation & Folding**: Document outline symbols (`textDocument/documentSymbol`) for directives and rules, plus folding ranges for multi-line rules and consecutive comment blocks.

## Requirements

- Python `>= 3.15`
- `cacl-compiler`
- `pygls >= 2.0.0`

## Installation

From the monorepo root with `uv`:

```bash
uv sync
```

Or install the package directly:

```bash
pip install ./packages/cacl-lsp
```

## Usage

Run over stdio (default, used by editor clients):

```bash
cacl-lsp --stdio
```

Or run over TCP or via Python module invocation:

```bash
cacl-lsp --tcp --host 127.0.0.1 --port 2087
python -m cacl_lsp --stdio
```

### CLI Options

| Option | Default | Description |
| --- | --- | --- |
| `--stdio` | `true` | Communicate over standard input/output |
| `--tcp` | `false` | Listen on a TCP socket instead of stdio |
| `--host` | `127.0.0.1` | TCP bind host when `--tcp` is set |
| `--port` | `2087` | TCP bind port when `--tcp` is set |
| `--log-file` | `None` | Optional file path for server logs (defaults to `stderr`) |
| `--log-level` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--version` | — | Print server version and exit |

## Configuration

`cacl-lsp` pulls workspace settings under the `cacl` configuration section (matching the VS Code extension settings):

| Setting | Default | Description |
| --- | --- | --- |
| `cacl.compiler.targetObjectType` | `"none"` | Optional object context (`"none"`, `"directory"`, `"document"`) for `W205` scope-applicability checks |
| `cacl.format.preserveComments` | `true` | Preserve `#` comments during formatting |
| `cacl.format.foldPresets` | `false` | Greedily fold atomic operation subsets into CEP 2 preset macros |
| `cacl.format.preferToSyntax` | `true` | Render positive principal-only disjunctions with `to ...` shorthand |
| `cacl.format.omitDefaultScope` | `true` | Omit the implicit `on all` clause when formatting |
| `cacl.format.alwaysEmitInherit` | `true` | Always emit an explicit `inherit on;` / `inherit off;` directive |
| `cacl.inlayHints.enabled` | `true` | Enable bitmask, implicit `on all`, and `expired` inlay hints |

## Testing

```bash
uv run pytest packages/cacl-lsp/tests
```

## License

Licensed under the [MIT License](./LICENSE).
