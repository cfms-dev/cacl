# vscode-cacl

Visual Studio Code extension providing TextMate syntax highlighting and Language Server Protocol (LSP) support for **CFMS Access Control Language (CACL)** (`.cacl` files), per [CEP 2](https://ceps.readthedocs.io/en/latest/cep-0002).

## Features

- **Syntax Highlighting & Editing Basics**: TextMate grammar (`source.cacl`) and bracket/comment rules (`#` line comments, `[...]`, `(...)`, `"..."`) for `.cacl` files.
- **Full LSP Support** (powered by [`cacl-lsp`](../../packages/cacl-lsp/README.md)):
  - Real-time syntax and semantic diagnostics (`E1xx`, `E2xx`, `E302`, `W2xx`)
  - Context-aware auto-completion (keywords, atomic operations, preset macros, scopes, predicates, RFC 3339 timestamp snippets)
  - Hover documentation with operation bitmasks, target/state applicability, and macro expansions
  - Semantic token highlighting
  - Comment-preserving document formatting
  - Quick fixes and refactoring code actions (`to` <-> `when`, expand/fold preset macros, duplicate cleanup, typo fixes)
  - Inlay hints for resolved operation bitmasks, implicit `on all` scopes, and expired `until` timestamps
  - Document outline symbols and code folding ranges

## Requirements

- Visual Studio Code `^1.146.0`
- [`cacl-lsp`](../../packages/cacl-lsp/README.md) available to the extension

### Language Server Discovery

On activation, the extension automatically resolves `cacl-lsp` in the following order:

1. Explicit `cacl.server.command` setting (supports `${workspaceFolder}` expansion) with optional `cacl.server.args`.
2. Local `.venv` inside open workspace folders (searching up to 4 parent directories for monorepo setups: `.venv\Scripts\cacl-lsp.exe` on Windows, `.venv/bin/cacl-lsp` on POSIX).
3. `cacl-lsp` executable found on `PATH`.
4. Fallback to `uv run cacl-lsp --stdio` when `uv` is available on `PATH`.

## Extension Settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `cacl.server.command` | `string` | `""` | Path or executable name of `cacl-lsp`. Leave empty for auto-detection. |
| `cacl.server.args` | `string[]` | `[]` | Extra CLI arguments passed to `cacl-lsp` (e.g. `["--log-level", "DEBUG"]`). |
| `cacl.server.trace.server` | `string` | `"off"` | Trace LSP communication (`"off"`, `"messages"`, `"verbose"`). |
| `cacl.compiler.targetObjectType` | `string` | `"none"` | Optional target object type (`"none"`, `"directory"`, `"document"`) for `W205` scope diagnostics. |
| `cacl.format.preserveComments` | `boolean` | `true` | Preserve leading, inline, and trailing `#` comments when formatting. |
| `cacl.format.foldPresets` | `boolean` | `false` | Greedily fold exact atomic operation subsets into CEP 2 preset macros when formatting. |
| `cacl.format.preferToSyntax` | `boolean` | `true` | Render positive principal-only disjunctions with `to ...` shorthand instead of `when ...`. |
| `cacl.format.omitDefaultScope` | `boolean` | `true` | Omit the implicit default `on all` scope clause when formatting. |
| `cacl.format.alwaysEmitInherit` | `boolean` | `true` | Always emit an explicit `inherit on;` / `inherit off;` directive when formatting. |
| `cacl.inlayHints.enabled` | `boolean` | `true` | Show inline hints for resolved macro/subtraction bitmasks, implicit `on all` scopes, and expired rules. |

## Commands

- **`CACL: Restart Language Server`** (`cacl.restartServer`): Stops and restarts the `cacl-lsp` language server client.

## Development & Packaging

From the monorepo root (or inside `editors/vscode-cacl`):

```bash
pnpm install
pnpm --filter vscode-cacl typecheck
pnpm --filter vscode-cacl test
pnpm --filter vscode-cacl build
```

Other available scripts inside `editors/vscode-cacl`:

- `pnpm watch` — rebuild extension bundle on changes
- `pnpm package` — create a `.vsix` package via `vsce package --no-dependencies`

## License

Licensed under the [MIT License](./LICENSE).
