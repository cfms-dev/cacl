export type PredicateKind = "user" | "group" | "perm";

export interface ConditionAtom {
  readonly kind: PredicateKind;
  readonly value: string;
  readonly negated: boolean;
}

export interface DNFClause {
  readonly atoms: readonly ConditionAtom[];
}

export type BoolIR =
  | { readonly type: "const"; readonly value: boolean }
  | { readonly type: "atom"; readonly atom: ConditionAtom }
  | { readonly type: "not"; readonly operand: BoolIR }
  | { readonly type: "and"; readonly left: BoolIR; readonly right: BoolIR }
  | { readonly type: "or"; readonly left: BoolIR; readonly right: BoolIR };

export interface DNFResult {
  readonly clauses: readonly DNFClause[];
  readonly hadUserExclusivityContradiction: boolean;
  readonly wasAbsorbedByAny: boolean;
  readonly simplifiedToTautology: boolean;
}

export class DNFComplexityError extends Error {
  constructor(maxClauses: number) {
    super(`DNF expansion exceeded safety limit of ${maxClauses} clauses.`);
    this.name = "DNFComplexityError";
  }
}

function atomKey(atom: ConditionAtom): string {
  return `${atom.kind}\0${atom.value}\0${atom.negated ? "1" : "0"}`;
}

function compareAtoms(a: ConditionAtom, b: ConditionAtom): number {
  if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
  if (a.value !== b.value) return a.value < b.value ? -1 : 1;
  if (a.negated !== b.negated) return a.negated ? 1 : -1;
  return 0;
}

function compareAtomArrays(a: readonly ConditionAtom[], b: readonly ConditionAtom[]): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const cmp = compareAtoms(a[i], b[i]);
    if (cmp !== 0) return cmp;
  }
  return a.length - b.length;
}

type ClauseMap = Map<string, ConditionAtom>;

function clauseKey(clause: ClauseMap): string {
  if (clause.size === 0) return "";
  const keys = Array.from(clause.keys()).sort();
  return keys.join("\x01");
}

function isSubset(sub: ClauseMap, sup: ClauseMap): boolean {
  if (sub.size > sup.size) return false;
  for (const key of sub.keys()) {
    if (!sup.has(key)) return false;
  }
  return true;
}

function toNnf(node: BoolIR, negated = false): BoolIR {
  switch (node.type) {
    case "const":
      return { type: "const", value: negated ? !node.value : node.value };
    case "atom":
      return {
        type: "atom",
        atom: {
          kind: node.atom.kind,
          value: node.atom.value,
          negated: negated ? !node.atom.negated : node.atom.negated,
        },
      };
    case "not":
      return toNnf(node.operand, !negated);
    case "and":
      return negated
        ? { type: "or", left: toNnf(node.left, true), right: toNnf(node.right, true) }
        : { type: "and", left: toNnf(node.left, false), right: toNnf(node.right, false) };
    case "or":
      return negated
        ? { type: "and", left: toNnf(node.left, true), right: toNnf(node.right, true) }
        : { type: "or", left: toNnf(node.left, false), right: toNnf(node.right, false) };
  }
}

function simplifyClause(raw: ClauseMap): {
  clause: ClauseMap | null;
  hadUserExclusivityContradiction: boolean;
} {
  for (const atom of raw.values()) {
    const compKey = atomKey({ kind: atom.kind, value: atom.value, negated: !atom.negated });
    if (raw.has(compKey)) {
      return { clause: null, hadUserExclusivityContradiction: false };
    }
  }

  let positiveUserCount = 0;
  for (const atom of raw.values()) {
    if (atom.kind === "user" && !atom.negated) {
      positiveUserCount++;
      if (positiveUserCount > 1) {
        return { clause: null, hadUserExclusivityContradiction: true };
      }
    }
  }

  if (positiveUserCount === 1) {
    const filtered: ClauseMap = new Map();
    for (const [k, atom] of raw.entries()) {
      if (!(atom.kind === "user" && atom.negated)) {
        filtered.set(k, atom);
      }
    }
    return { clause: filtered, hadUserExclusivityContradiction: false };
  }

  return { clause: raw, hadUserExclusivityContradiction: false };
}

function subsumeClauses(clauses: ClauseMap[]): ClauseMap[] {
  const dedup = new Map<string, ClauseMap>();
  for (const c of clauses) {
    dedup.set(clauseKey(c), c);
  }
  const unique = Array.from(dedup.values()).sort((a, b) => a.size - b.size);
  const kept: ClauseMap[] = [];
  for (const c of unique) {
    if (kept.some((existing) => isSubset(existing, c))) {
      continue;
    }
    kept.push(c);
  }
  return kept;
}

function minimizeDnfClauses(clauses: ClauseMap[]): ClauseMap[] {
  let current = subsumeClauses(clauses);

  while (current.length > 0) {
    if (current.some((c) => c.size === 0)) {
      return [new Map()];
    }

    let changed = false;

    // 1. Unit-complement absorption: {P} absorbs `not P` from other clauses
    const unitComplements = new Set<string>();
    for (const c of current) {
      if (c.size === 1) {
        const atom = c.values().next().value!;
        unitComplements.add(atomKey({ kind: atom.kind, value: atom.value, negated: !atom.negated }));
      }
    }

    if (unitComplements.size > 0) {
      const absorbed: ClauseMap[] = [];
      for (const c of current) {
        if (c.size > 1) {
          let hasMatch = false;
          for (const k of c.keys()) {
            if (unitComplements.has(k)) {
              hasMatch = true;
              break;
            }
          }
          if (hasMatch) {
            const reduced: ClauseMap = new Map();
            for (const [k, v] of c.entries()) {
              if (!unitComplements.has(k)) reduced.set(k, v);
            }
            absorbed.push(reduced);
            changed = true;
            continue;
          }
        }
        absorbed.push(c);
      }
      if (changed) {
        current = subsumeClauses(absorbed);
        continue;
      }
    }

    // 2. Complementary pair resolution: (C | {P}) or (C | {not P}) ==> C
    const clauseKeys = new Set(current.map((c) => clauseKey(c)));
    const resolved: ClauseMap[] = [];
    for (const c of current) {
      for (const [k, atom] of c.entries()) {
        if (!atom.negated) {
          const partnerMap: ClauseMap = new Map(c);
          partnerMap.delete(k);
          const negAtom: ConditionAtom = { kind: atom.kind, value: atom.value, negated: true };
          partnerMap.set(atomKey(negAtom), negAtom);
          if (clauseKeys.has(clauseKey(partnerMap))) {
            const ctx: ClauseMap = new Map(c);
            ctx.delete(k);
            resolved.push(ctx);
            changed = true;
          }
        }
      }
    }
    if (changed) {
      current = subsumeClauses([...current, ...resolved]);
      continue;
    }

    // 3. User-exclusivity tautology: (C and not user(A)) or (C and not user(B)) ==> C
    const negUserContexts = new Map<string, { ctx: ClauseMap; uids: Set<string> }>();
    for (const c of current) {
      for (const [k, atom] of c.entries()) {
        if (atom.kind === "user" && atom.negated) {
          const ctx: ClauseMap = new Map(c);
          ctx.delete(k);
          const ctxKey = clauseKey(ctx);
          let entry = negUserContexts.get(ctxKey);
          if (!entry) {
            entry = { ctx, uids: new Set() };
            negUserContexts.set(ctxKey, entry);
          }
          entry.uids.add(atom.value);
        }
      }
    }

    const userResolved: ClauseMap[] = [];
    for (const { ctx, uids } of negUserContexts.values()) {
      if (uids.size >= 2) {
        userResolved.push(ctx);
      }
    }
    if (userResolved.length > 0) {
      current = subsumeClauses([...current, ...userResolved]);
      continue;
    }

    break;
  }

  return current;
}

export function lowerToDnf(root: BoolIR, maxClauses = 256): DNFResult {
  const nnf = toNnf(root);
  const isLiteralAny = nnf.type === "const" && nnf.value;
  let userContradiction = false;
  let sawNonEmptyAlongsideAny = false;

  function expand(node: BoolIR): ClauseMap[] {
    switch (node.type) {
      case "const":
        return node.value ? [new Map()] : [];
      case "atom": {
        const m: ClauseMap = new Map();
        m.set(atomKey(node.atom), node.atom);
        return [m];
      }
      case "or": {
        const left = expand(node.left);
        const right = expand(node.right);
        const combined = [...left, ...right];
        const hasEmpty = combined.some((c) => c.size === 0);
        const hasNonEmpty = combined.some((c) => c.size > 0);
        if (hasEmpty && hasNonEmpty) {
          sawNonEmptyAlongsideAny = true;
        }
        const reduced = minimizeDnfClauses(combined);
        if (reduced.length > maxClauses) {
          throw new DNFComplexityError(maxClauses);
        }
        return reduced;
      }
      case "and": {
        const left = expand(node.left);
        const right = expand(node.right);
        if (left.length === 0 || right.length === 0) {
          return [];
        }
        let product: ClauseMap[] = [];
        for (const lc of left) {
          for (const rc of right) {
            const mergedMap: ClauseMap = new Map(lc);
            for (const [k, v] of rc.entries()) {
              mergedMap.set(k, v);
            }
            const { clause, hadUserExclusivityContradiction } = simplifyClause(mergedMap);
            if (hadUserExclusivityContradiction) {
              userContradiction = true;
            }
            if (clause !== null) {
              product.push(clause);
            }
            if (product.length > maxClauses * 4) {
              product = minimizeDnfClauses(product);
              if (product.length > maxClauses) {
                throw new DNFComplexityError(maxClauses);
              }
            }
          }
        }
        const reduced = minimizeDnfClauses(product);
        if (reduced.length > maxClauses) {
          throw new DNFComplexityError(maxClauses);
        }
        return reduced;
      }
      default:
        throw new Error(`Unexpected NNF node: ${(node as BoolIR).type}`);
    }
  }

  const rawClauses = minimizeDnfClauses(expand(nnf));
  const sortedAtomLists = rawClauses
    .map((c) => Array.from(c.values()).sort(compareAtoms))
    .sort(compareAtomArrays);

  const clauses: DNFClause[] = sortedAtomLists.map((atoms) => ({ atoms }));
  const simplifiedToTautology =
    clauses.length === 1 &&
    clauses[0].atoms.length === 0 &&
    !isLiteralAny &&
    !sawNonEmptyAlongsideAny;

  return {
    clauses,
    hadUserExclusivityContradiction: userContradiction,
    wasAbsorbedByAny: sawNonEmptyAlongsideAny,
    simplifiedToTautology,
  };
}

export function dnfClausesKey(clauses: readonly DNFClause[]): string {
  return clauses
    .map((c) => c.atoms.map((a) => atomKey(a)).join("&"))
    .join("|");
}
