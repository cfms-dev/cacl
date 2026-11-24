import type { SyntaxNode, Tree } from "@lezer/common";
import { dateToUtcUs, parseRfc3339UtcUs } from "./datetime";
import {
  type BoolIR,
  type DNFClause,
  DNFComplexityError,
  dnfClausesKey,
  lowerToDnf,
  type PredicateKind,
} from "./dnf";
import { parseCanonicalUuid } from "./identity";
import { parser } from "./parser";
import {
  ATOMIC_OP_BY_NAME,
  DEFAULT_PRESET_MACROS,
  DIR_APPLICABLE_MASK,
  DIR_ONLY_MASK,
  DOC_APPLICABLE_MASK,
  DOC_ONLY_MASK,
  maskToAtomicNames,
  type ObjectType,
} from "./permissions";

export type CaclSeverity = "error" | "warning" | "info";
export type CaclDiagnosticTag = "unnecessary" | "deprecated";
export type Effect = "allow" | "deny";
export type Scope = "self" | "dirs" | "docs" | "all";

export interface SpanRange {
  readonly from: number;
  readonly to: number;
}

export interface CaclDiagnostic {
  readonly code: string;
  readonly severity: CaclSeverity;
  readonly from: number;
  readonly to: number;
  readonly message: string;
  readonly hint?: string;
  readonly tags?: readonly CaclDiagnosticTag[];
}

export interface CaclAnalyzerOptions {
  /** Optional target object type context ("directory" or "document") for W205 diagnostics. */
  targetObjectType?: ObjectType | null;
  /** Reference UTC clock for W209 expired-rule warnings (defaults to current time). */
  nowUtc?: Date;
  /** Custom permission macro table override (defaults to CEP 2 presets). */
  macros?: Readonly<Record<string, number>>;
  /** Safety limit for DNF expansion (defaults to 256). */
  maxDnfClauses?: number;
  /** Whether to emit warning-level diagnostics (defaults to true). */
  includeWarnings?: boolean;
}

export interface ParsedOpItem {
  readonly name: string;
  readonly subtract: boolean;
  readonly from: number;
  readonly to: number;
}

export interface ParsedRuleMeta {
  readonly from: number;
  readonly to: number;
  readonly opSetFrom: number;
  readonly opSetTo: number;
  readonly opItems: readonly ParsedOpItem[];
  readonly toClauseFrom?: number;
  readonly toClauseTo?: number;
  readonly toItems: readonly SpanRange[];
}

export interface CaclAnalysisResult {
  readonly ok: boolean;
  readonly diagnostics: readonly CaclDiagnostic[];
  readonly directiveRanges: readonly SpanRange[];
  readonly ruleMetas: readonly ParsedRuleMeta[];
}

const UNNECESSARY_CODES = new Set([
  "W201",
  "W202",
  "W206",
  "W207",
  "W208",
  "W211",
  "W212",
]);
const DEPRECATED_CODES = new Set(["W209"]);

const ESCAPE_MAP: Readonly<Record<string, string>> = {
  '"': '"',
  "\\": "\\",
  n: "\n",
  r: "\r",
  t: "\t",
};

function makeDiagnostic(
  code: string,
  severity: CaclSeverity,
  from: number,
  to: number,
  message: string,
  hint?: string,
): CaclDiagnostic {
  const tags: CaclDiagnosticTag[] = [];
  if (UNNECESSARY_CODES.has(code)) tags.push("unnecessary");
  if (DEPRECATED_CODES.has(code)) tags.push("deprecated");
  return {
    code,
    severity,
    from,
    to,
    message,
    ...(hint ? { hint } : {}),
    ...(tags.length > 0 ? { tags } : {}),
  };
}

function unescapeCaclString(
  source: string,
  node: SyntaxNode,
  diagnostics: CaclDiagnostic[],
): string {
  const tokenText = source.slice(node.from, node.to);
  if (tokenText.length < 2 || !tokenText.startsWith('"') || !tokenText.endsWith('"')) {
    return "";
  }
  const raw = tokenText.slice(1, -1);
  const baseOffset = node.from + 1;
  let out = "";
  let i = 0;
  while (i < raw.length) {
    const ch = raw[i];
    if (ch === "\\") {
      if (i + 1 >= raw.length) {
        diagnostics.push(
          makeDiagnostic(
            "E102",
            "error",
            baseOffset + i,
            baseOffset + i + 1,
            "Unterminated escape sequence in string literal.",
          ),
        );
        break;
      }
      const nxt = raw[i + 1];
      const mapped = ESCAPE_MAP[nxt];
      if (mapped === undefined) {
        diagnostics.push(
          makeDiagnostic(
            "E102",
            "error",
            baseOffset + i,
            baseOffset + i + 2,
            `Unsupported escape sequence '\\${nxt}' in string literal.`,
            'Allowed escapes in CACL are: \\", \\\\, \\n, \\r, \\t.',
          ),
        );
        out += nxt;
      } else {
        out += mapped;
      }
      i += 2;
    } else {
      out += ch;
      i += 1;
    }
  }
  return out;
}

function subtreeHasError(node: SyntaxNode): boolean {
  const cursor = node.cursor();
  do {
    if (cursor.type.isError) return true;
  } while (cursor.next() && cursor.from < node.to);
  return false;
}

function collectSyntaxErrors(tree: Tree, source: string, diagnostics: CaclDiagnostic[]): void {
  const cursor = tree.cursor();
  do {
    if (cursor.type.isError) {
      let from = cursor.from;
      let to = cursor.to;
      if (from === to) {
        if (from < source.length) {
          to = from + 1;
        } else if (source.length > 0) {
          from = source.length - 1;
          to = source.length;
        }
      }
      const snippet = source.slice(from, Math.min(to, from + 20)).replace(/\s+/g, " ");
      const msg = snippet
        ? `Syntax error near '${snippet}'.`
        : "Unexpected syntax or incomplete CACL statement.";
      diagnostics.push(makeDiagnostic("E101", "error", from, to, msg));
    }
  } while (cursor.next());
}

function getChildren(node: SyntaxNode): SyntaxNode[] {
  const children: SyntaxNode[] = [];
  let child = node.firstChild;
  while (child) {
    children.push(child);
    child = child.nextSibling;
  }
  return children;
}

interface CompiledRuleInfo {
  effect: Effect;
  permissionMask: number;
  scope: Scope;
  dnfClauses: readonly DNFClause[];
  isUnconditional: boolean;
  validFromUs: bigint | null;
  validUntilUs: bigint | null;
  from: number;
  to: number;
  semanticKey: string;
}

function buildBoolIrFromNode(
  node: SyntaxNode,
  source: string,
  diagnostics: CaclDiagnostic[],
): BoolIR {
  switch (node.name) {
    case "BoolExpr":
    case "Atom":
    case "Principal":
    case "ParenExpr": {
      const inner = getChildren(node).find(
        (c) =>
          c.name === "OrExpr" ||
          c.name === "AndExpr" ||
          c.name === "NotExpr" ||
          c.name === "NegExpr" ||
          c.name === "Atom" ||
          c.name === "PrincipalPred" ||
          c.name === "PermPred" ||
          c.name === "AnyPred" ||
          c.name === "ParenExpr" ||
          c.name === "BoolExpr",
      );
      if (!inner) return { type: "const", value: true };
      return buildBoolIrFromNode(inner, source, diagnostics);
    }
    case "OrExpr": {
      const parts = getChildren(node).filter((c) => c.name === "AndExpr");
      if (parts.length === 0) return { type: "const", value: true };
      let expr = buildBoolIrFromNode(parts[0], source, diagnostics);
      for (let i = 1; i < parts.length; i++) {
        expr = { type: "or", left: expr, right: buildBoolIrFromNode(parts[i], source, diagnostics) };
      }
      return expr;
    }
    case "AndExpr": {
      const parts = getChildren(node).filter((c) => c.name === "NotExpr");
      if (parts.length === 0) return { type: "const", value: true };
      let expr = buildBoolIrFromNode(parts[0], source, diagnostics);
      for (let i = 1; i < parts.length; i++) {
        expr = { type: "and", left: expr, right: buildBoolIrFromNode(parts[i], source, diagnostics) };
      }
      return expr;
    }
    case "NotExpr": {
      const child = getChildren(node).find((c) => c.name === "NegExpr" || c.name === "Atom");
      if (!child) return { type: "const", value: true };
      return buildBoolIrFromNode(child, source, diagnostics);
    }
    case "NegExpr": {
      const operand = getChildren(node).find((c) => c.name === "NotExpr");
      if (!operand) return { type: "const", value: true };
      return { type: "not", operand: buildBoolIrFromNode(operand, source, diagnostics) };
    }
    case "AnyPred":
      return { type: "const", value: true };
    case "PrincipalPred":
    case "PermPred": {
      const kindNode = node.getChild("PrincipalKind") ?? node.getChild("PermKind");
      const strNode = node.getChild("String");
      const kind = (kindNode ? source.slice(kindNode.from, kindNode.to) : "perm") as PredicateKind;
      const raw = strNode ? unescapeCaclString(source, strNode, diagnostics) : "";

      if (!raw) {
        diagnostics.push(
          makeDiagnostic(
            "E204",
            "error",
            node.from,
            node.to,
            `Predicate '${kind}(...)' cannot have an empty identifier.`,
          ),
        );
        return { type: "atom", atom: { kind, value: raw, negated: false } };
      }

      if (kind === "user") {
        const parsedUuid = parseCanonicalUuid(raw);
        if (parsedUuid === null) {
          diagnostics.push(
            makeDiagnostic(
              "E302",
              "error",
              node.from,
              node.to,
              `User identifier '${raw}' is not a valid 36-character hyphenated RFC 9562 UUID.`,
              "Use a canonical 8-4-4-4-12 hexadecimal UUID; mutable usernames are prohibited in CACL syntax.",
            ),
          );
          return { type: "atom", atom: { kind, value: raw, negated: false } };
        }
        return { type: "atom", atom: { kind, value: parsedUuid, negated: false } };
      }

      return { type: "atom", atom: { kind, value: raw, negated: false } };
    }
    default:
      return { type: "const", value: true };
  }
}

function checkScopeCompatibility(
  scope: Scope,
  scopeSpan: SpanRange | null,
  opSetSpan: SpanRange,
  ruleSpan: SpanRange,
  mask: number,
  targetObjectType: ObjectType | null | undefined,
  diagnostics: CaclDiagnostic[],
): void {
  if (mask !== 0) {
    if (scope === "dirs" && (mask & DIR_APPLICABLE_MASK) === 0) {
      const target = scopeSpan ?? opSetSpan;
      diagnostics.push(
        makeDiagnostic(
          "W204",
          "warning",
          target.from,
          target.to,
          "Scope 'on dirs' has no effect: no operation in the set applies to directories.",
        ),
      );
    } else if (scope === "docs" && (mask & DOC_APPLICABLE_MASK) === 0) {
      const target = scopeSpan ?? opSetSpan;
      diagnostics.push(
        makeDiagnostic(
          "W203",
          "warning",
          target.from,
          target.to,
          "Scope 'on docs' has no effect: no operation in the set applies to documents.",
        ),
      );
    }
  }

  if (targetObjectType === "document") {
    if (scope === "dirs") {
      const target = scopeSpan ?? ruleSpan;
      diagnostics.push(
        makeDiagnostic(
          "W205",
          "warning",
          target.from,
          target.to,
          "Scope 'on dirs' attached to a document matches nothing.",
        ),
      );
    } else if (scope === "self" && (mask & DIR_ONLY_MASK) !== 0) {
      const names = maskToAtomicNames(mask & DIR_ONLY_MASK).join(", ");
      diagnostics.push(
        makeDiagnostic(
          "W205",
          "warning",
          opSetSpan.from,
          opSetSpan.to,
          `Directory-only operations [${names}] have no effect on a document with 'on self'.`,
        ),
      );
    }
  } else if (
    targetObjectType === "directory" &&
    scope === "self" &&
    (mask & DOC_ONLY_MASK) !== 0
  ) {
    const names = maskToAtomicNames(mask & DOC_ONLY_MASK).join(", ");
    diagnostics.push(
      makeDiagnostic(
        "W205",
        "warning",
        opSetSpan.from,
        opSetSpan.to,
        `Document-only operations [${names}] have no effect on a directory with 'on self'.`,
      ),
    );
  }
}

/**
 * Analyze a pre-parsed Lezer syntax tree and CACL source string without calling any server.
 */
export function analyzeTree(
  tree: Tree,
  source: string,
  options: CaclAnalyzerOptions = {},
): CaclAnalysisResult {
  const macros = options.macros ?? DEFAULT_PRESET_MACROS;
  const maxDnfClauses = options.maxDnfClauses ?? 256;
  const nowUtcUs = dateToUtcUs(options.nowUtc ?? new Date());
  const includeWarnings = options.includeWarnings ?? true;

  const allDiags: CaclDiagnostic[] = [];
  collectSyntaxErrors(tree, source, allDiags);

  const directiveRanges: SpanRange[] = [];
  const ruleMetas: ParsedRuleMeta[] = [];
  const compiledRules: CompiledRuleInfo[] = [];

  const top = tree.topNode;
  const topChildren = getChildren(top);

  // 1. Directive uniqueness check (E201)
  const validDirectives = topChildren.filter(
    (c) => c.name === "Directive" && !subtreeHasError(c),
  );
  for (const d of validDirectives) {
    directiveRanges.push({ from: d.from, to: d.to });
  }
  if (validDirectives.length > 1) {
    for (let i = 1; i < validDirectives.length; i++) {
      const dup = validDirectives[i];
      allDiags.push(
        makeDiagnostic(
          "E201",
          "error",
          dup.from,
          dup.to,
          "Duplicate 'inherit' directive; at most one is permitted per policy.",
        ),
      );
    }
  }

  // 2. Validate & compile each valid Rule node
  for (const child of topChildren) {
    if (child.name !== "Rule") continue;
    if (subtreeHasError(child)) {
      // Still validate string escapes inside broken rules
      const cur = child.cursor();
      do {
        if (cur.name === "String") {
          unescapeCaclString(source, cur.node, allDiags);
        }
      } while (cur.next() && cur.from < child.to);
      continue;
    }

    const effectNode = child.getChild("Effect");
    const effectText = effectNode ? source.slice(effectNode.from, effectNode.to).trim() : "allow";
    const effect: Effect = effectText === "deny" ? "deny" : "allow";

    const opSetNode = child.getChild("OpSet");
    if (!opSetNode) continue;

    const opItems: ParsedOpItem[] = [];
    let mask = 0;
    const opItemNodes = getChildren(opSetNode).filter((n) => n.name === "OpItem");

    for (let idx = 0; idx < opItemNodes.length; idx++) {
      const itemNode = opItemNodes[idx];
      const subNode = itemNode.getChild("OpSub");
      const addNode = itemNode.getChild("OpAdd");
      const subtract = subNode !== null;
      const identWrap = (subNode ?? addNode)?.getChild("OpIdent");
      const identNode = identWrap
        ? identWrap.getChild("PresetMacro") ??
          identWrap.getChild("AtomicOp") ??
          identWrap.getChild("UpperIdent")
        : null;
      const name = identNode ? source.slice(identNode.from, identNode.to) : "";
      opItems.push({ name, subtract, from: itemNode.from, to: itemNode.to });

      const atomicMeta = ATOMIC_OP_BY_NAME.get(name);
      let itemMask: number;
      if (atomicMeta !== undefined) {
        itemMask = atomicMeta.bit;
      } else if (Object.prototype.hasOwnProperty.call(macros, name)) {
        itemMask = macros[name];
      } else {
        allDiags.push(
          makeDiagnostic(
            "E202",
            "error",
            itemNode.from,
            itemNode.to,
            `Unknown atomic operation or permission macro '${name}'.`,
          ),
        );
        continue;
      }

      if (subtract) {
        if (idx === 0) {
          allDiags.push(
            makeDiagnostic(
              "E210",
              "error",
              itemNode.from,
              itemNode.to,
              `The leading operation item must not be negative ('-${name}').`,
              "Start the operation set with an unsigned operation or macro.",
            ),
          );
          continue;
        }
        if ((mask & itemMask) !== itemMask) {
          const missing = maskToAtomicNames(itemMask & ~mask).join(", ");
          allDiags.push(
            makeDiagnostic(
              "W201",
              "warning",
              itemNode.from,
              itemNode.to,
              `Subtracting '-${name}' removes bits that are not currently present: [${missing}].`,
            ),
          );
        }
        mask &= ~itemMask;
      } else {
        if ((mask & itemMask) === itemMask) {
          allDiags.push(
            makeDiagnostic(
              "W202",
              "warning",
              itemNode.from,
              itemNode.to,
              `Adding '${name}' is redundant; all of its bits are already present.`,
            ),
          );
        }
        mask |= itemMask;
      }
    }

    if (mask === 0) {
      allDiags.push(
        makeDiagnostic(
          "E203",
          "error",
          opSetNode.from,
          opSetNode.to,
          "Operation set evaluates to an empty bitmask (0x000000).",
          "A rule must grant or deny at least one effective atomic operation.",
        ),
      );
    }

    // Scope clause
    const scopeClauseNode = child.getChild("ScopeClause");
    const scopeNode = scopeClauseNode?.getChild("Scope") ?? null;
    const scopeText = scopeNode ? source.slice(scopeNode.from, scopeNode.to).trim() : "all";
    const scope: Scope =
      scopeText === "self" || scopeText === "dirs" || scopeText === "docs" ? scopeText : "all";
    const scopeSpan = scopeNode ? { from: scopeNode.from, to: scopeNode.to } : null;

    checkScopeCompatibility(
      scope,
      scopeSpan,
      { from: opSetNode.from, to: opSetNode.to },
      { from: child.from, to: child.to },
      mask,
      options.targetObjectType,
      allDiags,
    );

    // Match clause
    const matchNode = child.getChild("MatchClause");
    const principalListNode = matchNode?.getChild("PrincipalList") ?? null;
    const boolExprNode = matchNode?.getChild("BoolExpr") ?? null;

    const toItems: SpanRange[] = [];
    let boolIr: BoolIR = { type: "const", value: true };

    if (principalListNode) {
      const principals = getChildren(principalListNode).filter((n) => n.name === "Principal");
      const seenTo = new Set<string>();
      const irItems: BoolIR[] = [];

      for (const pNode of principals) {
        toItems.push({ from: pNode.from, to: pNode.to });
        const permPred = pNode.getChild("PermPred");
        const principalPred = pNode.getChild("PrincipalPred");

        if (permPred) {
          const strNode = permPred.getChild("String");
          const rawVal = strNode ? unescapeCaclString(source, strNode, allDiags) : "";
          allDiags.push(
            makeDiagnostic(
              "E205",
              "error",
              pNode.from,
              pNode.to,
              "Capability predicate 'perm(...)' is only allowed in 'when' clauses, not 'to'.",
              `Use: when perm("${rawVal}")`,
            ),
          );
        }

        const predNode = principalPred ?? permPred;
        if (predNode) {
          const kindNode = predNode.getChild("PrincipalKind") ?? predNode.getChild("PermKind");
          const strNode = predNode.getChild("String");
          const kind = (kindNode ? source.slice(kindNode.from, kindNode.to) : "perm") as PredicateKind;
          const rawVal = strNode ? unescapeCaclString(source, strNode, allDiags) : "";
          const normVal = kind === "user" ? rawVal.toLowerCase() : rawVal;
          const dedupKey = `${kind}\0${normVal}`;
          if (seenTo.has(dedupKey)) {
            allDiags.push(
              makeDiagnostic(
                "W208",
                "warning",
                pNode.from,
                pNode.to,
                `Duplicate principal '${kind}("${rawVal}")' in 'to' list.`,
              ),
            );
          }
          seenTo.add(dedupKey);
        }

        irItems.push(buildBoolIrFromNode(pNode, source, allDiags));
      }

      if (irItems.length > 0) {
        boolIr = irItems[0];
        for (let i = 1; i < irItems.length; i++) {
          boolIr = { type: "or", left: boolIr, right: irItems[i] };
        }
      }
    } else if (boolExprNode) {
      boolIr = buildBoolIrFromNode(boolExprNode, source, allDiags);
    }

    ruleMetas.push({
      from: child.from,
      to: child.to,
      opSetFrom: opSetNode.from,
      opSetTo: opSetNode.to,
      opItems,
      ...(matchNode && principalListNode
        ? { toClauseFrom: matchNode.from, toClauseTo: principalListNode.to }
        : {}),
      toItems,
    });

    // DNF lowering
    let dnfRes;
    const matchSpan: SpanRange = principalListNode
      ? { from: principalListNode.from, to: principalListNode.to }
      : boolExprNode
        ? { from: boolExprNode.from, to: boolExprNode.to }
        : { from: child.from, to: child.to };

    try {
      dnfRes = lowerToDnf(boolIr, maxDnfClauses);
    } catch (err) {
      if (err instanceof DNFComplexityError) {
        allDiags.push(
          makeDiagnostic(
            "E208",
            "error",
            matchSpan.from,
            matchSpan.to,
            err.message,
            "Simplify deeply nested boolean expressions or split into multiple rules.",
          ),
        );
        continue;
      }
      throw err;
    }

    if (dnfRes.clauses.length === 0) {
      const reason = dnfRes.hadUserExclusivityContradiction
        ? "a single subject cannot simultaneously hold two distinct user UUIDs"
        : "the boolean condition is a logical contradiction (always FALSE)";
      allDiags.push(
        makeDiagnostic(
          "W206",
          "warning",
          matchSpan.from,
          matchSpan.to,
          `Dead rule: condition is unsatisfiable (${reason}).`,
        ),
      );
    } else if (dnfRes.wasAbsorbedByAny) {
      allDiags.push(
        makeDiagnostic(
          "W207",
          "warning",
          matchSpan.from,
          matchSpan.to,
          "Condition contains 'any' in a disjunction; other branches are trivially absorbed.",
        ),
      );
    } else if (dnfRes.simplifiedToTautology) {
      allDiags.push(
        makeDiagnostic(
          "W213",
          "warning",
          matchSpan.from,
          matchSpan.to,
          "Condition is a logical tautology (always TRUE) and simplifies to 'any'.",
        ),
      );
    }

    // Time window validation
    const timeNode = child.getChild("TimeClause");
    let validFromUs: bigint | null = null;
    let validUntilUs: bigint | null = null;
    let invalidTimeWindow = false;

    if (timeNode) {
      const validFromNode = timeNode.getChild("ValidFrom");
      const validUntilNode = timeNode.getChild("ValidUntil");
      const fromStrNode = validFromNode?.getChild("String") ?? null;
      const untilStrNode = validUntilNode?.getChild("String") ?? null;

      if (fromStrNode) {
        const rawFrom = unescapeCaclString(source, fromStrNode, allDiags);
        validFromUs = parseRfc3339UtcUs(rawFrom);
        if (validFromUs === null) {
          invalidTimeWindow = true;
          allDiags.push(
            makeDiagnostic(
              "E206",
              "error",
              fromStrNode.from,
              fromStrNode.to,
              `Invalid RFC 3339 timestamp in 'from': '${rawFrom}'.`,
              'Include an explicit timezone offset, e.g. "2026-11-23T00:00:00Z".',
            ),
          );
        }
      }

      if (untilStrNode) {
        const rawUntil = unescapeCaclString(source, untilStrNode, allDiags);
        validUntilUs = parseRfc3339UtcUs(rawUntil);
        if (validUntilUs === null) {
          invalidTimeWindow = true;
          allDiags.push(
            makeDiagnostic(
              "E206",
              "error",
              untilStrNode.from,
              untilStrNode.to,
              `Invalid RFC 3339 timestamp in 'until': '${rawUntil}'.`,
              'Include an explicit timezone offset, e.g. "2026-12-31T23:59:59Z".',
            ),
          );
        }
      }

      if (validFromUs !== null && validUntilUs !== null && validFromUs >= validUntilUs) {
        invalidTimeWindow = true;
        allDiags.push(
          makeDiagnostic(
            "E207",
            "error",
            timeNode.from,
            timeNode.to,
            "Inverted or empty time window: 'from' must be strictly earlier than 'until' (half-open interval [from, until)).",
          ),
        );
      }

      if (validUntilUs !== null && validUntilUs <= nowUtcUs) {
        const target = untilStrNode ?? timeNode;
        allDiags.push(
          makeDiagnostic(
            "W209",
            "warning",
            target.from,
            target.to,
            "Rule has already expired relative to compile-time UTC clock.",
          ),
        );
      }

      if (effect === "deny" && validUntilUs !== null) {
        const target = untilStrNode ?? timeNode;
        allDiags.push(
          makeDiagnostic(
            "W210",
            "warning",
            target.from,
            target.to,
            "Temporary 'deny' rule with 'until': once expired, inherited or peer 'allow' rules will automatically resume granting access.",
          ),
        );
      }
    }

    // Remark string escape validation
    const remarkNode = child.getChild("RemarkClause");
    const remarkStrNode = remarkNode?.getChild("String") ?? null;
    if (remarkStrNode) {
      unescapeCaclString(source, remarkStrNode, allDiags);
    }

    if (mask === 0 || invalidTimeWindow) {
      continue;
    }

    const isUnconditional =
      dnfRes.clauses.length === 1 && dnfRes.clauses[0].atoms.length === 0;
    const semanticKey = [
      effect,
      mask.toString(16),
      scope,
      dnfClausesKey(dnfRes.clauses),
      validFromUs?.toString() ?? "",
      validUntilUs?.toString() ?? "",
    ].join("\x02");

    compiledRules.push({
      effect,
      permissionMask: mask,
      scope,
      dnfClauses: dnfRes.clauses,
      isUnconditional,
      validFromUs,
      validUntilUs,
      from: child.from,
      to: child.to,
      semanticKey,
    });
  }

  // 3. Cross-rule analysis: duplicate rules (W211) & global deny shadowing (W212)
  const seenRules = new Map<string, number>();
  for (let idx = 0; idx < compiledRules.length; idx++) {
    const cr = compiledRules[idx];
    const firstIdx = seenRules.get(cr.semanticKey);
    if (firstIdx !== undefined) {
      allDiags.push(
        makeDiagnostic(
          "W211",
          "warning",
          cr.from,
          cr.to,
          `Rule is semantically identical to rule #${firstIdx + 1}.`,
        ),
      );
    } else {
      seenRules.set(cr.semanticKey, idx);
    }
  }

  let globalDenyMask = 0;
  for (const cr of compiledRules) {
    if (
      cr.effect === "deny" &&
      cr.scope === "all" &&
      cr.isUnconditional &&
      cr.validFromUs === null &&
      cr.validUntilUs === null
    ) {
      globalDenyMask |= cr.permissionMask;
    }
  }

  if (globalDenyMask !== 0) {
    for (const cr of compiledRules) {
      if (cr.effect === "allow" && (cr.permissionMask & globalDenyMask) !== 0) {
        const shadowed = maskToAtomicNames(cr.permissionMask & globalDenyMask).join(", ");
        allDiags.push(
          makeDiagnostic(
            "W212",
            "warning",
            cr.from,
            cr.to,
            `Allow rule permissions [${shadowed}] are permanently overridden by an unconditional 'deny ... on all to any' rule in the same policy.`,
          ),
        );
      }
    }
  }

  const filtered = includeWarnings
    ? allDiags
    : allDiags.filter((d) => d.severity !== "warning");

  filtered.sort((a, b) => a.from - b.from || a.to - b.to);

  return {
    ok: !allDiags.some((d) => d.severity === "error"),
    diagnostics: filtered,
    directiveRanges,
    ruleMetas,
  };
}

/**
 * Headless entry point: parse and statically analyze a CACL policy string in pure JS/TS.
 */
export function analyzeCacl(
  source: string,
  options: CaclAnalyzerOptions = {},
): CaclAnalysisResult {
  const tree = parser.parse(source);
  return analyzeTree(tree, source, options);
}
