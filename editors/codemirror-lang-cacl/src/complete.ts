import type { Completion, CompletionContext, CompletionResult } from "@codemirror/autocomplete";
import { syntaxTree } from "@codemirror/language";
import {
  ATOMIC_OP_TABLE,
  DEFAULT_PRESET_MACROS,
  PRESET_MACRO_DESCRIPTIONS,
} from "./permissions";

const MACRO_COMPLETIONS: readonly Completion[] = Object.keys(DEFAULT_PRESET_MACROS).map(
  (name) => ({
    label: name,
    type: "constant",
    detail: "preset macro",
    info: PRESET_MACRO_DESCRIPTIONS[name],
    boost: 2,
  }),
);

const ATOMIC_OP_COMPLETIONS: readonly Completion[] = ATOMIC_OP_TABLE.map((op) => ({
  label: op.name,
  type: "enum",
  detail: `${op.target} (${op.state})`,
  info: op.description,
  boost: 1,
}));

const SCOPE_COMPLETIONS: readonly Completion[] = [
  { label: "all", type: "type", detail: "attached node and all descendants (default)" },
  { label: "self", type: "type", detail: "attached object only" },
  { label: "dirs", type: "type", detail: "descendant directories" },
  { label: "docs", type: "type", detail: "descendant documents" },
];

const INHERIT_STATE_COMPLETIONS: readonly Completion[] = [
  { label: "on", type: "keyword", detail: "inherit parent ACL policies (default)" },
  { label: "off", type: "keyword", detail: "break ACL inheritance from parent" },
];

const PREDICATE_AND_LOGIC_COMPLETIONS: readonly Completion[] = [
  { label: 'user("")', type: "function", detail: "RFC 9562 UUID principal", apply: 'user("")' },
  { label: 'group("")', type: "function", detail: "group identifier principal", apply: 'group("")' },
  { label: 'perm("")', type: "function", detail: "capability predicate (when only)", apply: 'perm("")' },
  { label: "any", type: "keyword", detail: "match any subject" },
  { label: "and", type: "keyword", detail: "logical conjunction" },
  { label: "or", type: "keyword", detail: "logical disjunction" },
  { label: "not", type: "keyword", detail: "logical negation" },
];

const TO_PRINCIPAL_COMPLETIONS: readonly Completion[] = [
  { label: 'user("")', type: "function", detail: "RFC 9562 UUID principal", apply: 'user("")' },
  { label: 'group("")', type: "function", detail: "group identifier principal", apply: 'group("")' },
  { label: "any", type: "keyword", detail: "match any subject" },
];

const TOP_LEVEL_COMPLETIONS: readonly Completion[] = [
  { label: "allow", type: "keyword", detail: "grant permissions" },
  { label: "deny", type: "keyword", detail: "deny permissions (overrides allow)" },
  { label: "inherit", type: "keyword", detail: "ACL inheritance directive" },
];

const RULE_CLAUSE_COMPLETIONS: readonly Completion[] = [
  { label: "on", type: "keyword", detail: "target scope clause" },
  { label: "to", type: "keyword", detail: "principal list shorthand" },
  { label: "when", type: "keyword", detail: "boolean condition expression" },
  { label: "from", type: "keyword", detail: "RFC 3339 start timestamp (inclusive)" },
  { label: "until", type: "keyword", detail: "RFC 3339 end timestamp (exclusive)" },
  { label: "remark", type: "keyword", detail: "human-readable rule comment" },
];

function hasAncestor(node: { name: string; parent: any } | null, target: string): boolean {
  let cur = node;
  while (cur) {
    if (cur.name === target) return true;
    cur = cur.parent;
  }
  return false;
}

/**
 * Context-aware CACL autocompletion source powered by the Lezer syntax tree.
 */
export function caclCompletionSource(
  context: CompletionContext,
): CompletionResult | null {
  const tree = syntaxTree(context.state);
  const node = tree.resolveInner(context.pos, -1);

  if (node.name === "String" || node.name === "Comment") {
    return null;
  }

  const word = context.matchBefore(/[A-Za-z_][A-Za-z0-9_]*/);
  if (!word && !context.explicit) {
    return null;
  }
  const from = word ? word.from : context.pos;

  // Check immediate preceding non-whitespace text for contextual keywords
  const beforeCursor = context.state.sliceDoc(Math.max(0, from - 32), from);

  if (/\binherit\s+$/.test(beforeCursor) || hasAncestor(node, "InheritState")) {
    return { from, options: INHERIT_STATE_COMPLETIONS };
  }

  if (/\bon\s+$/.test(beforeCursor) || hasAncestor(node, "ScopeClause")) {
    return { from, options: SCOPE_COMPLETIONS };
  }

  if (hasAncestor(node, "OpSet")) {
    return {
      from,
      options: [...MACRO_COMPLETIONS, ...ATOMIC_OP_COMPLETIONS],
      validFor: /^[A-Z0-9_]*$/,
    };
  }

  if (hasAncestor(node, "PrincipalList") || /\bto\s+$/.test(beforeCursor)) {
    return { from, options: TO_PRINCIPAL_COMPLETIONS };
  }

  if (hasAncestor(node, "BoolExpr") || /\bwhen\s+$/.test(beforeCursor)) {
    return { from, options: PREDICATE_AND_LOGIC_COMPLETIONS };
  }

  if (hasAncestor(node, "Rule")) {
    return {
      from,
      options: [...RULE_CLAUSE_COMPLETIONS, ...PREDICATE_AND_LOGIC_COMPLETIONS],
    };
  }

  return {
    from,
    options: TOP_LEVEL_COMPLETIONS,
  };
}
