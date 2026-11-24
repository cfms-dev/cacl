import { syntaxTree } from "@codemirror/language";
import { type Action, type Diagnostic, linter } from "@codemirror/lint";
import type { Extension } from "@codemirror/state";
import {
  analyzeTree,
  type CaclAnalysisResult,
  type CaclAnalyzerOptions,
  type CaclDiagnostic,
  type SpanRange,
} from "./analyzer";
import { ATOMIC_OP_BY_NAME, DEFAULT_PRESET_MACROS } from "./permissions";

export interface CaclLinterOptions extends CaclAnalyzerOptions {
  /** Whether to attach clickable Quick Fix actions to diagnostics (defaults to true). */
  enableQuickFixes?: boolean;
  /** Debounce delay in milliseconds passed to `@codemirror/lint` (defaults to 250ms). */
  delay?: number;
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const temp = dp[j];
      if (a[i - 1] === b[j - 1]) {
        dp[j] = prev;
      } else {
        dp[j] = 1 + Math.min(prev, dp[j], dp[j - 1]);
      }
      prev = temp;
    }
  }
  return dp[n];
}

function findCloseMatches(
  target: string,
  candidates: readonly string[],
  limit = 3,
): string[] {
  const upper = target.toUpperCase();
  const scored: { name: string; score: number }[] = [];
  for (const cand of candidates) {
    const dist = levenshtein(upper, cand);
    const maxLen = Math.max(upper.length, cand.length);
    const similarity = 1 - dist / Math.max(1, maxLen);
    if (similarity >= 0.45 || cand.includes(upper) || upper.includes(cand)) {
      scored.push({ name: cand, score: dist });
    }
  }
  scored.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));
  return scored.slice(0, limit).map((s) => s.name);
}

function wholeLineDeleteRange(source: string, span: SpanRange): SpanRange {
  const prevNl = source.lastIndexOf("\n", Math.max(0, span.from - 1));
  const lineStart = prevNl === -1 ? 0 : prevNl + 1;
  const beforeBlank = source.slice(lineStart, span.from).trim() === "";

  const nextNl = source.indexOf("\n", span.to);
  const lineEnd = nextNl === -1 ? source.length : nextNl;
  const afterBlank = source.slice(span.to, lineEnd).trim() === "";

  if (beforeBlank && afterBlank) {
    return {
      from: lineStart,
      to: nextNl === -1 ? source.length : nextNl + 1,
    };
  }
  return span;
}

function commaListDeleteRange(
  source: string,
  items: readonly SpanRange[],
  targetIdx: number,
): SpanRange {
  const item = items[targetIdx];
  if (targetIdx > 0) {
    const prevEnd = items[targetIdx - 1].to;
    const commaIdx = source.indexOf(",", prevEnd);
    if (commaIdx !== -1 && commaIdx < item.from) {
      return { from: commaIdx, to: item.to };
    }
  } else if (targetIdx + 1 < items.length) {
    const nextStart = items[targetIdx + 1].from;
    const commaIdx = source.indexOf(",", item.to);
    if (commaIdx !== -1 && commaIdx < nextStart) {
      let delEnd = commaIdx + 1;
      while (delEnd < nextStart && (source[delEnd] === " " || source[delEnd] === "\t")) {
        delEnd++;
      }
      return { from: item.from, to: delEnd };
    }
  }
  return item;
}

function buildQuickFixes(
  diag: CaclDiagnostic,
  source: string,
  analysis: CaclAnalysisResult,
  allOpAndMacroNames: readonly string[],
): Action[] {
  const actions: Action[] = [];

  if (diag.code === "E201") {
    const del = wholeLineDeleteRange(source, { from: diag.from, to: diag.to });
    actions.push({
      name: "Remove duplicate 'inherit'",
      apply(view) {
        view.dispatch({ changes: { from: del.from, to: del.to, insert: "" } });
      },
    });
  } else if (diag.code === "E202") {
    const raw = source.slice(diag.from, diag.to).trim();
    const hasMinus = raw.startsWith("-");
    const ident = hasMinus ? raw.slice(1).trim() : raw;
    for (const suggestion of findCloseMatches(ident, allOpAndMacroNames)) {
      const replacement = hasMinus ? `-${suggestion}` : suggestion;
      actions.push({
        name: `Use '${replacement}'`,
        apply(view, from, to) {
          view.dispatch({ changes: { from, to, insert: replacement } });
        },
      });
    }
  } else if (diag.code === "E205") {
    for (const rule of analysis.ruleMetas) {
      if (
        rule.toClauseFrom !== undefined &&
        rule.toClauseTo !== undefined &&
        diag.from >= rule.toClauseFrom &&
        diag.to <= rule.toClauseTo &&
        rule.toItems.length > 0
      ) {
        const replacement =
          "when " + rule.toItems.map((s) => source.slice(s.from, s.to).trim()).join(" or ");
        const repFrom = rule.toClauseFrom;
        const repTo = rule.toClauseTo;
        actions.push({
          name: "Convert 'to' to 'when'",
          apply(view) {
            view.dispatch({ changes: { from: repFrom, to: repTo, insert: replacement } });
          },
        });
        break;
      }
    }
  } else if (diag.code === "W201" || diag.code === "W202") {
    for (const rule of analysis.ruleMetas) {
      if (rule.opItems.length <= 1) continue;
      const idx = rule.opItems.findIndex(
        (item) => item.from === diag.from && item.to === diag.to,
      );
      if (idx !== -1) {
        const del = commaListDeleteRange(source, rule.opItems, idx);
        const item = rule.opItems[idx];
        const label = item.subtract ? `-${item.name}` : item.name;
        actions.push({
          name: `Remove '${label}'`,
          apply(view) {
            view.dispatch({ changes: { from: del.from, to: del.to, insert: "" } });
          },
        });
        break;
      }
    }
  } else if (diag.code === "W208") {
    for (const rule of analysis.ruleMetas) {
      if (rule.toItems.length <= 1) continue;
      const idx = rule.toItems.findIndex(
        (item) => item.from === diag.from && item.to === diag.to,
      );
      if (idx !== -1) {
        const del = commaListDeleteRange(source, rule.toItems, idx);
        actions.push({
          name: "Remove duplicate principal",
          apply(view) {
            view.dispatch({ changes: { from: del.from, to: del.to, insert: "" } });
          },
        });
        break;
      }
    }
  } else if (diag.code === "W211") {
    const del = wholeLineDeleteRange(source, { from: diag.from, to: diag.to });
    actions.push({
      name: "Remove duplicate rule",
      apply(view) {
        view.dispatch({ changes: { from: del.from, to: del.to, insert: "" } });
      },
    });
  }

  return actions;
}

/**
 * Convert a CACL analysis result into `@codemirror/lint` Diagnostic objects.
 */
export function toCodeMirrorDiagnostics(
  source: string,
  analysis: CaclAnalysisResult,
  options: CaclLinterOptions = {},
): Diagnostic[] {
  const enableQuickFixes = options.enableQuickFixes ?? true;
  const macros = options.macros ?? DEFAULT_PRESET_MACROS;
  const allOpAndMacroNames = [
    ...Object.keys(macros),
    ...Array.from(ATOMIC_OP_BY_NAME.keys()),
  ];

  return analysis.diagnostics.map((d) => {
    const message = d.hint ? `[${d.code}] ${d.message}\nHint: ${d.hint}` : `[${d.code}] ${d.message}`;
    const actions = enableQuickFixes
      ? buildQuickFixes(d, source, analysis, allOpAndMacroNames)
      : [];
    return {
      from: d.from,
      to: d.to,
      severity: d.severity,
      source: "cacl",
      message,
      ...(actions.length > 0 ? { actions } : {}),
    };
  });
}

/**
 * Pure client-side CodeMirror 6 linter extension for CACL.
 * Operates directly on the in-editor Lezer syntax tree with no LSP server required.
 */
export function caclLinter(options: CaclLinterOptions = {}): Extension {
  const { delay = 250, ...analyzerOpts } = options;
  return linter(
    (view) => {
      const source = view.state.doc.toString();
      const tree = syntaxTree(view.state);
      const analysis = analyzeTree(tree, source, analyzerOpts);
      return toCodeMirrorDiagnostics(source, analysis, options);
    },
    { delay },
  );
}
