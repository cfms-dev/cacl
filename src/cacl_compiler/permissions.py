from dataclasses import dataclass
from enum import Enum, IntFlag


class ObjectType(str, Enum):
    DIRECTORY = "directory"
    DOCUMENT = "document"


class ObjectState(str, Enum):
    NORMAL = "normal"
    SOFT_DELETED = "soft_deleted"


class TargetApplicability(str, Enum):
    DIRECTORY = "directory"
    DOCUMENT = "document"
    BOTH = "both"


class StateApplicability(str, Enum):
    NORMAL = "normal"
    SOFT_DELETED = "soft_deleted"
    BOTH = "both"


class AtomicOp(IntFlag):
    """21 orthogonal atomic operations defined in CEP-0002 (bits 0..20)."""

    # 2.1 Directory-Specific Operations (0..3)
    TRAVERSE = 1 << 0  # 0x000001
    LIST_DIRECTORY = 1 << 1  # 0x000002
    CREATE_DOCUMENT = 1 << 2  # 0x000004
    CREATE_DIRECTORY = 1 << 3  # 0x000008

    # 2.2 Document & Immutable Revision Operations (4..9)
    READ_CONTENT = 1 << 4  # 0x000010
    WRITE_CONTENT = 1 << 5  # 0x000020
    LIST_REVISIONS = 1 << 6  # 0x000040
    READ_REVISION = 1 << 7  # 0x000080
    SET_CURRENT_REVISION = 1 << 8  # 0x000100
    DELETE_REVISION = 1 << 9  # 0x000200

    # 2.3 Common Namespace & Metadata Operations (10..13)
    READ_METADATA = 1 << 10  # 0x000400
    WRITE_METADATA = 1 << 11  # 0x000800
    RENAME = 1 << 12  # 0x001000
    REPARENT = 1 << 13  # 0x002000

    # 2.4 Lifecycle & Trash Operations (14..18)
    DELETE = 1 << 14  # 0x004000
    DIRECTORY_DELETE_CHILD = 1 << 15  # 0x008000
    LIST_DELETED = 1 << 16  # 0x010000
    RESTORE = 1 << 17  # 0x020000
    PURGE = 1 << 18  # 0x040000

    # 2.5 Permission Governance Operations (19..20)
    READ_DACL = 1 << 19  # 0x080000
    WRITE_DACL = 1 << 20  # 0x100000


@dataclass(frozen=True, slots=True)
class AtomicOpMeta:
    op: AtomicOp
    bit_offset: int
    name: str
    target: TargetApplicability
    state: StateApplicability


ATOMIC_OP_TABLE: tuple[AtomicOpMeta, ...] = (
    # 2.1 Directory-Specific
    AtomicOpMeta(
        AtomicOp.TRAVERSE,
        0,
        "TRAVERSE",
        TargetApplicability.DIRECTORY,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.LIST_DIRECTORY,
        1,
        "LIST_DIRECTORY",
        TargetApplicability.DIRECTORY,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.CREATE_DOCUMENT,
        2,
        "CREATE_DOCUMENT",
        TargetApplicability.DIRECTORY,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.CREATE_DIRECTORY,
        3,
        "CREATE_DIRECTORY",
        TargetApplicability.DIRECTORY,
        StateApplicability.NORMAL,
    ),
    # 2.2 Document & Revisions
    AtomicOpMeta(
        AtomicOp.READ_CONTENT,
        4,
        "READ_CONTENT",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.WRITE_CONTENT,
        5,
        "WRITE_CONTENT",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.LIST_REVISIONS,
        6,
        "LIST_REVISIONS",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.READ_REVISION,
        7,
        "READ_REVISION",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.SET_CURRENT_REVISION,
        8,
        "SET_CURRENT_REVISION",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.DELETE_REVISION,
        9,
        "DELETE_REVISION",
        TargetApplicability.DOCUMENT,
        StateApplicability.NORMAL,
    ),
    # 2.3 Common Namespace & Metadata
    AtomicOpMeta(
        AtomicOp.READ_METADATA,
        10,
        "READ_METADATA",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.WRITE_METADATA,
        11,
        "WRITE_METADATA",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.RENAME,
        12,
        "RENAME",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.REPARENT,
        13,
        "REPARENT",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    # 2.4 Lifecycle & Trash
    AtomicOpMeta(
        AtomicOp.DELETE,
        14,
        "DELETE",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.DIRECTORY_DELETE_CHILD,
        15,
        "DIRECTORY_DELETE_CHILD",
        TargetApplicability.DIRECTORY,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.LIST_DELETED,
        16,
        "LIST_DELETED",
        TargetApplicability.DIRECTORY,
        StateApplicability.BOTH,
    ),
    AtomicOpMeta(
        AtomicOp.RESTORE,
        17,
        "RESTORE",
        TargetApplicability.BOTH,
        StateApplicability.SOFT_DELETED,
    ),
    AtomicOpMeta(
        AtomicOp.PURGE,
        18,
        "PURGE",
        TargetApplicability.BOTH,
        StateApplicability.SOFT_DELETED,
    ),
    # 2.5 Permission Governance
    AtomicOpMeta(
        AtomicOp.READ_DACL,
        19,
        "READ_DACL",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
    AtomicOpMeta(
        AtomicOp.WRITE_DACL,
        20,
        "WRITE_DACL",
        TargetApplicability.BOTH,
        StateApplicability.NORMAL,
    ),
)

ATOMIC_OP_BY_NAME: dict[str, AtomicOpMeta] = {m.name: m for m in ATOMIC_OP_TABLE}
ATOMIC_OP_BY_FLAG: dict[AtomicOp, AtomicOpMeta] = {m.op: m for m in ATOMIC_OP_TABLE}

ALL_ATOMIC_MASK: int = (1 << 21) - 1
DIR_ONLY_MASK: int = sum(
    int(m.op) for m in ATOMIC_OP_TABLE if m.target is TargetApplicability.DIRECTORY
)
DOC_ONLY_MASK: int = sum(
    int(m.op) for m in ATOMIC_OP_TABLE if m.target is TargetApplicability.DOCUMENT
)
SHARED_MASK: int = sum(
    int(m.op) for m in ATOMIC_OP_TABLE if m.target is TargetApplicability.BOTH
)

# Predefined Permission Macros (expanded deterministically at compile time)
_CREATE_CHILD = AtomicOp.CREATE_DOCUMENT | AtomicOp.CREATE_DIRECTORY
_MOVE = AtomicOp.RENAME | AtomicOp.REPARENT
_PRESET_READ = (
    AtomicOp.TRAVERSE
    | AtomicOp.LIST_DIRECTORY
    | AtomicOp.READ_CONTENT
    | AtomicOp.READ_METADATA
)
_PRESET_WRITE = (
    _CREATE_CHILD
    | _MOVE
    | AtomicOp.WRITE_CONTENT
    | AtomicOp.WRITE_METADATA
    | AtomicOp.LIST_REVISIONS
    | AtomicOp.SET_CURRENT_REVISION
    | AtomicOp.DELETE
)
_PRESET_EDIT = _PRESET_READ | _PRESET_WRITE
_PRESET_TRASH_MANAGE = (
    AtomicOp.LIST_DELETED
    | AtomicOp.RESTORE
    | AtomicOp.PURGE
    | AtomicOp.DIRECTORY_DELETE_CHILD
)
_PRESET_ACL_MANAGE = AtomicOp.READ_DACL | AtomicOp.WRITE_DACL

DEFAULT_PRESET_MACROS: dict[str, int] = {
    "CREATE_CHILD": int(_CREATE_CHILD),
    "MOVE": int(_MOVE),
    "PRESET_READ": int(_PRESET_READ),
    "PRESET_WRITE": int(_PRESET_WRITE),
    "PRESET_EDIT": int(_PRESET_EDIT),
    "PRESET_RW": int(_PRESET_EDIT),  # Alias retained for compatibility
    "PRESET_TRASH_MANAGE": int(_PRESET_TRASH_MANAGE),
    "PRESET_ACL_MANAGE": int(_PRESET_ACL_MANAGE),
}


def mask_to_atomic_names(mask: int) -> list[str]:
    """Decompose an integer bitmask into canonical bit-offset ordered atomic names."""
    return [m.name for m in ATOMIC_OP_TABLE if mask & int(m.op)]


def mask_to_folded_tokens(
    mask: int,
    macros: dict[str, int] | None = None,
    prefer_macro_order: tuple[str, ...] = (
        "PRESET_EDIT",
        "PRESET_READ",
        "PRESET_TRASH_MANAGE",
        "PRESET_ACL_MANAGE",
        "CREATE_CHILD",
        "MOVE",
    ),
) -> list[str]:
    """Greedily fold exact macro subsets for human-friendly formatting (lossless)."""
    table = DEFAULT_PRESET_MACROS if macros is None else macros
    remaining = mask
    tokens: list[str] = []
    for macro_name in prefer_macro_order:
        macro_mask = table.get(macro_name, 0)
        if macro_mask and (remaining & macro_mask) == macro_mask:
            tokens.append(macro_name)
            remaining &= ~macro_mask
    tokens.extend(mask_to_atomic_names(remaining))
    return tokens


def op_applies_to_object(op: AtomicOp, obj_type: ObjectType) -> bool:
    meta = ATOMIC_OP_BY_FLAG[op]
    if meta.target is TargetApplicability.BOTH:
        return True
    return meta.target.value == obj_type.value


def op_applies_to_state(op: AtomicOp, state: ObjectState) -> bool:
    meta = ATOMIC_OP_BY_FLAG[op]
    if meta.state is StateApplicability.BOTH:
        return True
    return meta.state.value == state.value
