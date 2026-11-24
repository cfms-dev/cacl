import {
  continuedIndent,
  foldInside,
  foldNodeProp,
  indentNodeProp,
  LanguageSupport,
  LRLanguage,
} from "@codemirror/language";
import type { Extension } from "@codemirror/state";
import { caclCompletionSource } from "./complete";
import { caclLinter, type CaclLinterOptions } from "./lint";
import { parser } from "./parser";

export {
  analyzeCacl,
  analyzeTree,
  type CaclAnalysisResult,
  type CaclAnalyzerOptions,
  type CaclDiagnostic,
  type CaclDiagnosticTag,
  type CaclSeverity,
  type Effect,
  type ParsedOpItem,
  type ParsedRuleMeta,
  type Scope,
  type SpanRange,
} from "./analyzer";
export { caclCompletionSource } from "./complete";
export { dateToUtcUs, parseRfc3339UtcUs } from "./datetime";
export {
  type BoolIR,
  type ConditionAtom,
  type DNFClause,
  DNFComplexityError,
  type DNFResult,
  lowerToDnf,
  type PredicateKind,
} from "./dnf";
export { caclHighlighting } from "./highlight";
export { parseCanonicalUuid } from "./identity";
export { caclLinter, type CaclLinterOptions, toCodeMirrorDiagnostics } from "./lint";
export { parser } from "./parser";
export {
  ALL_ATOMIC_MASK,
  ATOMIC_OP_BY_NAME,
  ATOMIC_OP_TABLE,
  type AtomicOpMeta,
  DEFAULT_PRESET_MACROS,
  DIR_APPLICABLE_MASK,
  DIR_ONLY_MASK,
  DOC_APPLICABLE_MASK,
  DOC_ONLY_MASK,
  maskToAtomicNames,
  maskToFoldedTokens,
  type ObjectType,
  PRESET_MACRO_DESCRIPTIONS,
  SHARED_MASK,
  type StateApplicability,
  type TargetApplicability,
} from "./permissions";

/**
 * Lezer-based CACL language definition for CodeMirror 6.
 */
export const caclLanguage = LRLanguage.define({
  name: "cacl",
  parser: parser.configure({
    props: [
      indentNodeProp.add({
        OpSet: continuedIndent({ except: /^\s*\]/ }),
        ParenExpr: continuedIndent({ except: /^\s*\)/ }),
        Rule: continuedIndent(),
      }),
      foldNodeProp.add({
        OpSet: foldInside,
        ParenExpr: foldInside,
      }),
    ],
  }),
  languageData: {
    commentTokens: { line: "#" },
    closeBrackets: { brackets: ["[", "(", '"'] },
    indentOnInput: /^\s*[\]\)]$/,
  },
});

export interface CaclSupportConfig {
  /**
   * Configure built-in client-side static checking (`@codemirror/lint`).
   * Enabled by default; pass `false` to disable or an options object to customize.
   */
  lint?: boolean | CaclLinterOptions;
  /**
   * Register context-aware CACL completions into `caclLanguage.data`
   * (active when `@codemirror/autocomplete` / `basicSetup` is used). Defaults to `true`.
   */
  autocomplete?: boolean;
}

/**
 * Full CodeMirror 6 language support for CACL:
 * - Lezer incremental syntax highlighting, bracket matching, folding, and indentation
 * - Pure client-side static checking & quick fixes via `@codemirror/lint` (no LSP required)
 * - Context-aware autocompletion data via `@codemirror/autocomplete`
 */
export function cacl(config: CaclSupportConfig = {}): LanguageSupport {
  const extensions: Extension[] = [];

  if (config.autocomplete !== false) {
    extensions.push(
      caclLanguage.data.of({
        autocomplete: caclCompletionSource,
      }),
    );
  }

  if (config.lint !== false) {
    const lintOptions = typeof config.lint === "object" ? config.lint : {};
    extensions.push(caclLinter(lintOptions));
  }

  return new LanguageSupport(caclLanguage, extensions);
}
