# `codemirror-lang-cacl`

Standalone **CodeMirror 6** language support for **CFMS Access Control Language (CACL / CEP 2)** providing:

- **Incremental Lezer LR(1) parsing & syntax highlighting** (`@lezer/lr`, `@lezer/highlight`) — distinguishes preset macros (`PRESET_RW`, `CREATE_CHILD`, etc.), 21 atomic operations, subtractive `-OP` modifiers, scopes (`self`, `dirs`, `docs`, `all`), predicates (`user`, `group`, `perm`), boolean operators, RFC 3339 timestamps, strings, and `#` comments, plus bracket matching, auto-closing pairs, folding, and indentation.
- **Pure client-side static checking & Quick Fixes** (`@codemirror/lint`) — implements all 22 CEP 2 diagnostic codes (`E101`–`E302`, `W201`–`W213`) directly in TypeScript in the browser or Node with **zero dependency on any Language Server (LSP) or Python runtime**.
- **Context-aware autocompletion** (`@codemirror/autocomplete`) — suggests preset macros, atomic operations, scopes, directives, predicates, and boolean keywords based on cursor syntax context.

## Installation

```bash
pnpm add codemirror-lang-cacl @codemirror/language @codemirror/lint @codemirror/state @codemirror/view
```

> **Note:** `@codemirror/*` packages are declared as `peerDependencies` (`^6.0.0`) so your bundler shares a single `@codemirror/state` instance across extensions.

## Quick Start

```ts
import { EditorState } from "@codemirror/state";
import { EditorView, basicSetup } from "codemirror";
import { lintGutter } from "@codemirror/lint";
import { cacl } from "codemirror-lang-cacl";

const view = new EditorView({
  state: EditorState.create({
    doc: `inherit on;\nallow [PRESET_RW, -DELETE] on docs to group("editors");\n`,
    extensions: [
      basicSetup,
      lintGutter(),
      cacl(),
    ],
  }),
  parent: document.getElementById("editor")!,
});
```

### Configuration

```ts
cacl({
  // Configure or disable the built-in client-side linter (enabled by default)
  lint: {
    targetObjectType: "directory", // "directory" | "document" | null (enables W205)
    includeWarnings: true,
    enableQuickFixes: true,
    delay: 250,
  },
  // Register CACL completions into caclLanguage.data (defaults to true)
  autocomplete: true,
});
```

### Headless Static Analysis (No Editor Required)

```ts
import { analyzeCacl } from "codemirror-lang-cacl";

const result = analyzeCacl('allow [TRAVERSE] to user("not-a-uuid");');
console.log(result.ok); // false
console.log(result.diagnostics); // [{ code: "E302", severity: "error", ... }]
```

## Diagnostic Coverage

| Code | Severity | Description |
| --- | --- | --- |
| `E101` | error | Syntax / parse error |
| `E102` | error | Unsupported or unterminated string escape sequence |
| `E201` | error | Duplicate `inherit` directive |
| `E202` | error | Unknown atomic operation or permission macro |
| `E203` | error | Operation set evaluates to empty bitmask (`0x000000`) |
| `E204` | error | Empty identifier in `user("")`, `group("")`, or `perm("")` |
| `E205` | error | `perm(...)` capability predicate used in `to` instead of `when` |
| `E206` | error | Invalid timezone-aware RFC 3339 timestamp |
| `E207` | error | Inverted or empty time window (`from >= until`) |
| `E208` | error | DNF boolean expansion exceeded safety clause limit |
| `E210` | error | Leading operation item cannot be negative (`-OP`) |
| `E302` | error | `user(...)` identifier is not a canonical 36-char RFC 9562 UUID |
| `W201` | warning | Subtracting `-OP` removes bits not currently present |
| `W202` | warning | Adding `OP` is redundant (bits already present) |
| `W203` | warning | `on docs` has no effect for directory-only operations |
| `W204` | warning | `on dirs` has no effect for document-only operations |
| `W205` | warning | Scope/operation mismatch with configured `targetObjectType` |
| `W206` | warning | Dead rule: unsatisfiable condition (contradiction / multiple `user()`) |
| `W207` | warning | `any` in disjunction trivially absorbs other branches |
| `W208` | warning | Duplicate principal in `to` list |
| `W209` | warning | Rule already expired relative to reference UTC clock |
| `W210` | warning | Temporary `deny` rule with `until` |
| `W211` | warning | Semantically duplicate rule |
| `W212` | warning | `allow` rule permanently overridden by unconditional `deny ... on all to any` |
| `W213` | warning | Boolean condition is a tautology and simplifies to `any` |

## License

MIT
