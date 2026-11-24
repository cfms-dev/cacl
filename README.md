# CACL Monorepo

CFMS Access Control Language (CACL) is a domain-specific language (DSL) for defining access control rules, as specified by [CEP 2](https://ceps.readthedocs.io/en/latest/cep-0002). This repository serves as a monorepo hosting the compiler toolchain, Language Server Protocol (LSP) server, and editor integrations for CACL.

## Packages

| Package | Path | Description | License |
| --- | --- | --- | --- |
| [`cacl-compiler`](./packages/cacl-compiler/README.md) | [`packages/cacl-compiler`](./packages/cacl-compiler) | Standalone parser, static analyzer, DNF compiler, decompiler/formatter, and `caclc` CLI | [MIT](./packages/cacl-compiler/LICENSE) |
| [`cacl-lsp`](./packages/cacl-lsp/README.md) | [`packages/cacl-lsp`](./packages/cacl-lsp) | Language Server Protocol (LSP) server for CACL built with `pygls` | [MIT](./packages/cacl-lsp/LICENSE) |
| [`vscode-cacl`](./editors/vscode-cacl/README.md) | [`editors/vscode-cacl`](./editors/vscode-cacl) | Visual Studio Code extension providing TextMate syntax highlighting and LSP integration | [MIT](./editors/vscode-cacl/LICENSE) |

## Language Overview

CACL policies control access over hierarchical CFMS directories and documents using explicit `allow` and `deny` rules (where `deny` always takes precedence over `allow`):

```cacl
# Optional inheritance directive (defaults to `inherit on;`, at most one per policy)
inherit on;

# Grant standard read/write access except DELETE on descendant documents
allow [PRESET_RW, -DELETE] on docs to group("editors")
    remark "Editors can read and update documents without deleting";

# Grant temporary administrative access using a boolean condition and RFC 3339 window
allow [PRESET_ACL_RW, RESTORE] on all
    when user("550e8400-e29b-41d4-a716-446655440000") and perm("security.audit")
    from "2026-01-01T00:00:00Z" until "2026-12-31T23:59:59Z"
    remark "Temporary ACL governance";

# Explicitly deny purging across the entire subtree
deny [PURGE] to any;
```

Key language features:

- **21 Atomic Operations & 7 Preset Macros**: Bitmask-based permission algebra with additive and subtractive (`-OP`) items.
- **Scopes**: `self` (attached node only), `dirs` (descendant directories), `docs` (descendant documents), and `all` (default when `on` is omitted).
- **Principals & Conditions**: Shorthand `to` principal lists (`user("<uuid>")`, `group("...")`, `any`) or full boolean `when` expressions (`and`, `or`, `not`, parentheses, and `perm("...")` capabilities). User identifiers must be canonical 36-character RFC 9562 UUIDs.
- **Temporal Windows**: Half-open `[from, until)` intervals using timezone-aware RFC 3339 timestamps.

## Development

### Prerequisites

- **Python** `>= 3.15` and **[uv](https://docs.astral.sh/uv/)** (for `cacl-compiler` and `cacl-lsp`)
- **Node.js** and **[pnpm](https://pnpm.io/)** (for `vscode-cacl`)

### Python Workspace (`cacl-compiler` & `cacl-lsp`)

Install workspace dependencies into `.venv` and run the full Python test suite:

```bash
uv sync
uv run pytest
```

Run the CLI tools directly from the workspace:

```bash
uv run caclc --help
uv run cacl-lsp --help
```

### VS Code Extension (`vscode-cacl`)

Install workspace Node dependencies, type-check, test, and bundle the extension:

```bash
pnpm install
pnpm --filter vscode-cacl typecheck
pnpm --filter vscode-cacl test
pnpm --filter vscode-cacl build
```

To package a `.vsix` archive:

```bash
pnpm --filter vscode-cacl package
```

## License

This repository and all of its sub-projects are licensed under the **MIT License**. See the root [LICENSE](./LICENSE) file for the full license text. Each distributable sub-project (`cacl-compiler`, `cacl-lsp`, and `vscode-cacl`) also includes its own copy of the MIT `LICENSE` file so standalone packages (PyPI distributions and `.vsix` bundles) retain their license notice.
