export type ObjectType = "directory" | "document";
export type TargetApplicability = "directory" | "document" | "both";
export type StateApplicability = "normal" | "soft_deleted" | "both";

export interface AtomicOpMeta {
  readonly name: string;
  readonly bitOffset: number;
  readonly bit: number;
  readonly target: TargetApplicability;
  readonly state: StateApplicability;
  readonly description: string;
}

export const ATOMIC_OP_TABLE: readonly AtomicOpMeta[] = [
  // 2.1 Directory-Specific (0..3)
  { name: "TRAVERSE", bitOffset: 0, bit: 1 << 0, target: "directory", state: "normal", description: "Traverse directory path segments" },
  { name: "LIST_DIRECTORY", bitOffset: 1, bit: 1 << 1, target: "directory", state: "normal", description: "List immediate children of a directory" },
  { name: "CREATE_DOCUMENT", bitOffset: 2, bit: 1 << 2, target: "directory", state: "normal", description: "Create a new document inside a directory" },
  { name: "CREATE_DIRECTORY", bitOffset: 3, bit: 1 << 3, target: "directory", state: "normal", description: "Create a new subdirectory inside a directory" },

  // 2.2 Document & Revisions (4..9)
  { name: "READ_CONTENT", bitOffset: 4, bit: 1 << 4, target: "document", state: "normal", description: "Read current document content" },
  { name: "WRITE_CONTENT", bitOffset: 5, bit: 1 << 5, target: "document", state: "normal", description: "Write or update document content" },
  { name: "LIST_REVISIONS", bitOffset: 6, bit: 1 << 6, target: "document", state: "normal", description: "List immutable document revisions" },
  { name: "READ_REVISION", bitOffset: 7, bit: 1 << 7, target: "document", state: "normal", description: "Read historical document revisions" },
  { name: "SET_CURRENT_REVISION", bitOffset: 8, bit: 1 << 8, target: "document", state: "normal", description: "Switch active document revision" },
  { name: "DELETE_REVISION", bitOffset: 9, bit: 1 << 9, target: "document", state: "normal", description: "Delete an immutable document revision" },

  // 2.3 Common Namespace & Metadata (10..13)
  { name: "READ_METADATA", bitOffset: 10, bit: 1 << 10, target: "both", state: "normal", description: "Read object metadata" },
  { name: "WRITE_METADATA", bitOffset: 11, bit: 1 << 11, target: "both", state: "normal", description: "Modify object metadata" },
  { name: "RENAME", bitOffset: 12, bit: 1 << 12, target: "both", state: "normal", description: "Rename object" },
  { name: "REPARENT", bitOffset: 13, bit: 1 << 13, target: "both", state: "normal", description: "Move object to another parent directory" },

  // 2.4 Lifecycle & Trash (14..18)
  { name: "DELETE", bitOffset: 14, bit: 1 << 14, target: "both", state: "normal", description: "Soft-delete object to trash" },
  { name: "DIRECTORY_DELETE_CHILD", bitOffset: 15, bit: 1 << 15, target: "directory", state: "normal", description: "Delete children within a directory" },
  { name: "LIST_DELETED", bitOffset: 16, bit: 1 << 16, target: "directory", state: "both", description: "List soft-deleted entries in a directory" },
  { name: "RESTORE", bitOffset: 17, bit: 1 << 17, target: "both", state: "soft_deleted", description: "Restore soft-deleted object from trash" },
  { name: "PURGE", bitOffset: 18, bit: 1 << 18, target: "both", state: "soft_deleted", description: "Permanently purge soft-deleted object" },

  // 2.5 Permission Governance (19..20)
  { name: "READ_DACL", bitOffset: 19, bit: 1 << 19, target: "both", state: "normal", description: "Read object discretionary ACL policy" },
  { name: "WRITE_DACL", bitOffset: 20, bit: 1 << 20, target: "both", state: "normal", description: "Modify object discretionary ACL policy" },
];

export const ATOMIC_OP_BY_NAME: ReadonlyMap<string, AtomicOpMeta> = new Map(
  ATOMIC_OP_TABLE.map((m) => [m.name, m]),
);

function sumBits(predicate: (m: AtomicOpMeta) => boolean): number {
  let mask = 0;
  for (const m of ATOMIC_OP_TABLE) {
    if (predicate(m)) mask |= m.bit;
  }
  return mask;
}

export const ALL_ATOMIC_MASK = (1 << 21) - 1;
export const DIR_ONLY_MASK = sumBits((m) => m.target === "directory");
export const DOC_ONLY_MASK = sumBits((m) => m.target === "document");
export const SHARED_MASK = sumBits((m) => m.target === "both");
export const DIR_APPLICABLE_MASK = DIR_ONLY_MASK | SHARED_MASK;
export const DOC_APPLICABLE_MASK = DOC_ONLY_MASK | SHARED_MASK;

const BIT = Object.fromEntries(ATOMIC_OP_TABLE.map((m) => [m.name, m.bit])) as Record<string, number>;

const CREATE_CHILD = BIT.CREATE_DOCUMENT | BIT.CREATE_DIRECTORY;
const MOVE = BIT.RENAME | BIT.REPARENT;
const PRESET_READ = BIT.TRAVERSE | BIT.LIST_DIRECTORY | BIT.READ_CONTENT | BIT.READ_METADATA;
const PRESET_WRITE =
  CREATE_CHILD |
  MOVE |
  BIT.WRITE_CONTENT |
  BIT.WRITE_METADATA |
  BIT.LIST_REVISIONS |
  BIT.SET_CURRENT_REVISION |
  BIT.DELETE;
const PRESET_RW = PRESET_READ | PRESET_WRITE;
const PRESET_TRASH_RW =
  BIT.LIST_DELETED | BIT.RESTORE | BIT.PURGE | BIT.DIRECTORY_DELETE_CHILD;
const PRESET_ACL_RW = BIT.READ_DACL | BIT.WRITE_DACL;

export const DEFAULT_PRESET_MACROS: Readonly<Record<string, number>> = {
  CREATE_CHILD,
  MOVE,
  PRESET_READ,
  PRESET_WRITE,
  PRESET_RW,
  PRESET_TRASH_RW,
  PRESET_ACL_RW,
};

export const PRESET_MACRO_DESCRIPTIONS: Readonly<Record<string, string>> = {
  CREATE_CHILD: "CREATE_DOCUMENT | CREATE_DIRECTORY",
  MOVE: "RENAME | REPARENT",
  PRESET_READ: "TRAVERSE | LIST_DIRECTORY | READ_CONTENT | READ_METADATA",
  PRESET_WRITE: "CREATE_CHILD | MOVE | WRITE_CONTENT | WRITE_METADATA | LIST_REVISIONS | SET_CURRENT_REVISION | DELETE",
  PRESET_RW: "PRESET_READ | PRESET_WRITE",
  PRESET_TRASH_RW: "LIST_DELETED | RESTORE | PURGE | DIRECTORY_DELETE_CHILD",
  PRESET_ACL_RW: "READ_DACL | WRITE_DACL",
};

export function maskToAtomicNames(mask: number): string[] {
  const names: string[] = [];
  for (const meta of ATOMIC_OP_TABLE) {
    if ((mask & meta.bit) !== 0) {
      names.push(meta.name);
    }
  }
  return names;
}

const DEFAULT_PREFER_MACRO_ORDER = [
  "PRESET_RW",
  "PRESET_READ",
  "PRESET_WRITE",
  "PRESET_TRASH_RW",
  "PRESET_ACL_RW",
  "CREATE_CHILD",
  "MOVE",
] as const;

export function maskToFoldedTokens(
  mask: number,
  macros: Readonly<Record<string, number>> = DEFAULT_PRESET_MACROS,
  preferMacroOrder: readonly string[] = DEFAULT_PREFER_MACRO_ORDER,
): string[] {
  let remaining = mask;
  const tokens: string[] = [];
  for (const macroName of preferMacroOrder) {
    const macroMask = macros[macroName] ?? 0;
    if (macroMask !== 0 && (remaining & macroMask) === macroMask) {
      tokens.push(macroName);
      remaining &= ~macroMask;
    }
  }
  tokens.push(...maskToAtomicNames(remaining));
  return tokens;
}
