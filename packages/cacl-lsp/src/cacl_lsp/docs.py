from cacl_compiler import (
    ATOMIC_OP_BY_NAME,
    DEFAULT_PRESET_MACROS,
)
from cacl_compiler.permissions import mask_to_atomic_names

ATOMIC_OP_DESCRIPTIONS: dict[str, str] = {
    "TRAVERSE": "Traverse through a directory to reach descendant paths.",
    "LIST_DIRECTORY": "List active child entries inside a directory.",
    "CREATE_DOCUMENT": "Create new documents directly inside a directory.",
    "CREATE_DIRECTORY": "Create new subdirectories directly inside a directory.",
    "READ_CONTENT": "Read the current content payload of a document.",
    "WRITE_CONTENT": "Append a new content revision to a document.",
    "LIST_REVISIONS": "List historical revisions of a document.",
    "READ_REVISION": "Read content of a specific historical revision.",
    "SET_CURRENT_REVISION": "Switch the active revision pointer of a document.",
    "DELETE_REVISION": "Permanently remove a historical document revision.",
    "READ_METADATA": "Read object metadata (name, timestamps, attributes).",
    "WRITE_METADATA": "Modify object metadata properties.",
    "RENAME": "Rename an object within its parent directory.",
    "REPARENT": "Move an object to a different parent directory.",
    "DELETE": "Soft-delete an object into the trash.",
    "DIRECTORY_DELETE_CHILD": "Delete child objects within a directory.",
    "LIST_DELETED": "List soft-deleted entries inside a directory.",
    "RESTORE": "Restore a soft-deleted object back to normal state.",
    "PURGE": "Permanently destroy a soft-deleted object.",
    "READ_DACL": "Read the CACL access control policy attached to an object.",
    "WRITE_DACL": "Modify the CACL access control policy attached to an object.",
}

MACRO_DESCRIPTIONS: dict[str, str] = {
    "CREATE_CHILD": "Create child documents or subdirectories inside a directory.",
    "MOVE": "Rename or reparent an object across directories.",
    "PRESET_READ": "Standard read-only access for traversing, listing, and reading content/metadata.",
    "PRESET_WRITE": "Standard write access (create, move, write content/metadata, manage current revision, soft-delete).",
    "PRESET_RW": "Combined standard read and write preset (`PRESET_READ | PRESET_WRITE`).",
    "PRESET_TRASH_RW": "Trash & lifecycle management preset (list deleted, restore, purge, delete child).",
    "PRESET_ACL_RW": "Permission governance preset (read and write DACL policies).",
}

SCOPE_DESCRIPTIONS: dict[str, str] = {
    "self": "Applies only to the node this policy is attached to (`distance == 0`).",
    "dirs": "Applies to child and descendant directories beneath this node.",
    "docs": "Applies to child and descendant documents beneath this node.",
    "all": "Applies to the node itself and all descendant directories and documents (default when `on` is omitted).",
}

KEYWORD_DESCRIPTIONS: dict[str, str] = {
    "inherit": "Controls whether ACL rules from ancestor nodes are inherited (`inherit on;` or `inherit off;`). At most one per policy.",
    "on": "In `inherit on;`: enables ancestor policy inheritance. In `on <scope>`: specifies target scope (`self`, `dirs`, `docs`, `all`).",
    "off": "Disables ancestor policy inheritance (`inherit off;`).",
    "allow": "Grants the resolved atomic operations when the rule condition matches (unless overridden by a matching `deny` rule).",
    "deny": "Explicitly denies the resolved atomic operations. Deny always takes precedence over `allow` in CEP 2.",
    "to": "Shorthand positive disjunction of principals (`user(...)`, `group(...)`, or `any`). Equivalent to `when p1 or p2`.",
    "when": "General boolean condition supporting `user(...)`, `group(...)`, `perm(...)`, `any`, `and`, `or`, `not`, and parentheses.",
    "from": "Inclusive start of the rule's validity window (`[from, until)`), specified as an RFC 3339 timestamp with timezone.",
    "until": "Exclusive end of the rule's validity window (`[from, until)`), specified as an RFC 3339 timestamp with timezone.",
    "remark": "Human-readable audit note attached to the compiled rule.",
    "and": "Boolean conjunction (binds tighter than `or`, looser than `not`).",
    "or": "Boolean disjunction (lowest precedence among boolean operators).",
    "not": "Boolean negation (highest precedence among boolean operators).",
    "any": "Universal wildcard predicate matching every subject (tautology).",
}

PREDICATE_DESCRIPTIONS: dict[str, str] = {
    "user": 'Matches a specific user by canonical 36-character hyphenated RFC 9562 UUID, e.g. `user("550e8400-e29b-41d4-a716-446655440000")`. Mutable usernames are prohibited.',
    "group": 'Matches subjects belonging to the specified group identifier, e.g. `group("engineering")`.',
    "perm": 'Matches subjects holding a system-level capability, e.g. `perm("audit.read_history")`. Only permitted in `when` clauses (not `to`).',
}


def format_atomic_op_markdown(name: str, *, subtracted: bool = False) -> str | None:
    meta = ATOMIC_OP_BY_NAME.get(name)
    if meta is None:
        return None
    desc = ATOMIC_OP_DESCRIPTIONS.get(name, "")
    mask_hex = f"0x{int(meta.op):06x}"
    header = f"### Atomic Operation `{'-' if subtracted else ''}{name}`"
    lines = [header]
    if desc:
        lines.append(desc)
    lines.append("")
    lines.append(f"- **Bit**: `{meta.bit_offset}` (`{mask_hex}`)")
    lines.append(f"- **Target**: `{meta.target.value}`")
    lines.append(f"- **State**: `{meta.state.value}`")
    if subtracted:
        lines.append("- **Effect in set**: Removes this bit from the accumulated operation mask.")
    return "\n".join(lines)


def format_macro_markdown(name: str, *, subtracted: bool = False) -> str | None:
    mask = DEFAULT_PRESET_MACROS.get(name)
    if mask is None:
        return None
    desc = MACRO_DESCRIPTIONS.get(name, "")
    ops = mask_to_atomic_names(mask)
    header = f"### Preset Macro `{'-' if subtracted else ''}{name}`"
    lines = [header]
    if desc:
        lines.append(desc)
    lines.append("")
    lines.append(f"- **Mask**: `0x{mask:06x}` ({len(ops)} atomic operations)")
    lines.append("- **Expands to**: " + ", ".join(f"`{op}`" for op in ops))
    if subtracted:
        lines.append("- **Effect in set**: Removes all constituent bits from the accumulated operation mask.")
    return "\n".join(lines)


def format_scope_markdown(name: str) -> str | None:
    desc = SCOPE_DESCRIPTIONS.get(name)
    if desc is None:
        return None
    return f"### Scope `on {name}`\n{desc}"


def format_predicate_markdown(name: str) -> str | None:
    desc = PREDICATE_DESCRIPTIONS.get(name)
    if desc is None:
        return None
    return f"### Predicate `{name}(...)`\n{desc}"


def format_keyword_markdown(name: str) -> str | None:
    desc = KEYWORD_DESCRIPTIONS.get(name)
    if desc is None:
        return None
    return f"### Keyword `{name}`\n{desc}"
