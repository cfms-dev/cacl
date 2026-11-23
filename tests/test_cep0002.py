"""Conformance tests for CEP 2 (CACL). Run: uv run --with pytest pytest"""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from cacl_compiler import (
    AtomicOp,
    CompilerConfig,
    DEFAULT_PRESET_MACROS,
    InMemoryPrincipalResolver,
    UserDirectoryEntry,
    NamespaceNode,
    ObjectState,
    ObjectType,
    Subject,
    compile_cacl,
    decompile_policy,
    evaluate_access,
    evaluate_reparent,
    evaluate_soft_delete,
)
from cacl_compiler.ast_nodes import Scope

GRAMMAR = Path(__file__).parents[1] / "src" / "cacl_compiler" / "cacl.lark"

EXAMPLE_A = '''
inherit on;
# comment
deny [READ_REVISION, DELETE_REVISION] on docs
  when not perm("history_audit")
  remark "Prevent historical snapshot leakage and audit trail tampering";
allow [PRESET_RW, -RENAME, -DELETE]
  to user("alice"), group("external_editors")
  remark "External collaborators restricted to content iteration";
allow [PRESET_TRASH_MANAGE] on dirs
  when (group("core_dev") and perm("vault_write")) or group("sec_auditors");
'''

EXAMPLE_B = '''
inherit off;
allow [TRAVERSE, CREATE_DOCUMENT] on self
  to group("all_employees")
  remark "Blind dropbox submission entry point";
allow [LIST_DIRECTORY] on self
  to group("review_board");
allow [READ_CONTENT, READ_METADATA] on docs
  to group("review_board")
  remark "Read-only inspection by the review board";
'''

EXAMPLE_C = '''
inherit on;
allow [PRESET_READ, LIST_REVISIONS] on docs
  to user("auditor_li")
  from "2026-12-01T00:00:00Z" until "2026-12-16T00:00:00Z"
  remark "2026 Q4 external audit window";
allow [PRESET_WRITE] on all
  when group("core_dev") and perm("vault_write")
  from "2027-01-01T00:00:00+08:00"
  remark "FY2027 scheduled write enablement";
deny [WRITE_CONTENT, DELETE, PURGE] on all
  when not group("sec_incident_commander")
  until "2026-11-25T12:00:00Z"
  remark "Temporary freeze during incident No.402";
'''

NOW = datetime(2026, 11, 24, tzinfo=UTC)

# A user identifier is always a UUID.
U_ALICE = UUID("11111111-1111-4111-8111-111111111111")
U_BOB = UUID("22222222-2222-4222-8222-222222222222")
U_LI = UUID("33333333-3333-4333-8333-333333333333")
DIRECTORY = InMemoryPrincipalResolver(
    users=[
        UserDirectoryEntry(U_ALICE, "alice"),
        UserDirectoryEntry(U_BOB, "bob"),
        UserDirectoryEntry(U_LI, "auditor_li"),
    ]
)


def compile_(src, **kw):
    return compile_cacl(src, CompilerConfig(now_utc=NOW, **kw))


def codes(res):
    return {d.code for d in res.diagnostics}


# --- Section 2/3: operations and macros -------------------------------------


def test_21_atomic_ops_fixed_bits():
    assert len(AtomicOp) == 21
    assert [op.value for op in AtomicOp] == [1 << i for i in range(21)]
    assert AtomicOp.WRITE_DACL == 0x100000 and AtomicOp.PURGE == 0x040000


def test_macros_exactly_as_specified():
    assert set(DEFAULT_PRESET_MACROS) == {
        "CREATE_CHILD", "MOVE", "PRESET_READ", "PRESET_WRITE", "PRESET_RW",
        "PRESET_TRASH_MANAGE", "PRESET_ACL_MANAGE",
    }  # fmt: skip
    m = DEFAULT_PRESET_MACROS
    assert m["PRESET_RW"] == m["PRESET_READ"] | m["PRESET_WRITE"]
    for excluded in ("READ_REVISION", "DELETE_REVISION", "PURGE", "READ_DACL", "WRITE_DACL"):
        assert not m["PRESET_WRITE"] & AtomicOp[excluded]
    assert not compile_('allow [PRESET_EDIT] to any;').ok


# --- Section 4: grammar -----------------------------------------------------


def test_grammar_matches_spec_text():
    text = GRAMMAR.read_text(encoding="utf-8")
    assert 'rule: effect op_set scope_clause? match_clause time_clause? remark_clause? ";"' in text
    assert "start: directive* rule*" in text


@pytest.mark.parametrize("src", [EXAMPLE_A, EXAMPLE_B, EXAMPLE_C])
def test_spec_examples_compile_with_directory(src):
    # The examples name users by username; the identity layer binds them to UUIDs.
    res = compile_(src, resolver=DIRECTORY)
    assert res.ok, res.diagnostics
    assert not res.errors


def test_to_equals_when_or():
    a = compile_(f'allow [TRAVERSE] to user("{U_ALICE}"), group("g");').policy
    b = compile_(f'allow [TRAVERSE] when user("{U_ALICE}") or group("g");').policy
    assert a.rules[0].dnf_clauses == b.rules[0].dnf_clauses


def test_perm_not_allowed_in_to():
    assert not compile_('allow [TRAVERSE] to perm("x");').ok


def test_default_scope_all_and_inherit_on():
    p = compile_('allow [TRAVERSE] to any;').policy
    assert p.inherit is True and p.rules[0].scope is Scope.ALL


def test_precedence_not_and_or():
    # not > and > or  ==>  a or (b and (not c))
    r = compile_('allow [TRAVERSE] when group("a") or group("b") and not group("c");').policy.rules[0]
    sets = {frozenset((a.value, a.negated) for a in c.atoms) for c in r.dnf_clauses}
    assert sets == {frozenset({("a", False)}), frozenset({("b", False), ("c", True)})}


# --- String literals ---------------------------------------------------------


def test_escapes_and_errors():
    ok = compile_(r'allow [TRAVERSE] to group("a\"b\\c\n\r\t");').policy
    assert ok.rules[0].dnf_clauses[0].atoms[0].value == 'a"b\\c\n\r\t'
    assert not compile_(r'allow [TRAVERSE] to group("a\qb");').ok
    assert not compile_(r'allow [TRAVERSE] to group("a\qb"); ').policy
    assert not compile_('allow [TRAVERSE] to group("a\nb");').ok


def test_escape_roundtrip():
    src = r'allow [TRAVERSE] to group("a\"b\\c\n\r\t") remark "x\ty";'
    p = compile_(src).policy
    p2 = compile_(decompile_policy(p)).policy
    assert p2.rules == p.rules


# --- 5.1 validation ----------------------------------------------------------


def test_duplicate_inherit_error():
    assert not compile_("inherit on; inherit off; allow [TRAVERSE] to any;").ok


def test_leading_negative_item_is_error():
    assert not compile_("allow [-RENAME, REPARENT] to any;").ok


def test_unknown_identifier_and_empty_mask_errors():
    assert "E202" in codes(compile_("allow [NOPE] to any;"))
    assert "E203" in codes(compile_("allow [RENAME, -RENAME] to any;"))


def test_subtracting_absent_bit_warns():
    res = compile_("allow [RENAME, -DELETE] to any;")
    assert res.ok and "W201" in codes(res)
    assert "W201" not in codes(compile_("allow [PRESET_RW, -RENAME] to any;"))
    assert "W201" in codes(compile_("allow [PRESET_READ, -MOVE] to any;"))


def test_scope_intersection_warnings():
    # no directory-applicable op under `on dirs`
    assert "W204" in codes(compile_("allow [READ_CONTENT] on dirs to any;"))
    # no document-applicable op under `on docs`
    assert "W203" in codes(compile_("allow [LIST_DIRECTORY] on docs to any;"))
    # mixed sets are fine (spec example C: PRESET_READ on docs)
    assert not codes(compile_("allow [PRESET_READ] on docs to any;")) & {"W203", "W204"}
    assert not codes(compile_("allow [PRESET_READ] on dirs to any;")) & {"W203", "W204"}
    # known Document target + `on dirs`
    res = compile_("allow [PRESET_READ] on dirs to any;", target_object_type=ObjectType.DOCUMENT)
    assert "W205" in codes(res)


def test_predicate_literals():
    assert not compile_('allow [TRAVERSE] to user("");').ok
    assert not compile_('allow [TRAVERSE] when perm("");').ok
    assert compile_('allow [TRAVERSE] to group(" ");').ok  # non-empty after unescaping


def test_user_identifier_must_be_uuid():
    res = compile_('allow [TRAVERSE] to user("alice");')
    assert not res.ok and "E302" in codes(res)
    assert not compile_('allow [TRAVERSE] to user("not-a-uuid");').ok
    assert not compile_('allow [TRAVERSE] when not user("1");').ok


def test_user_uuid_is_canonicalised():
    p = compile_(f'allow [TRAVERSE] to user("{str(U_ALICE).upper()}");').policy
    assert p.rules[0].dnf_clauses[0].atoms[0].value == str(U_ALICE)


def test_username_bound_to_uuid_via_resolver():
    p = compile_('allow [TRAVERSE] to user("alice");', resolver=DIRECTORY).policy
    assert p.rules[0].dnf_clauses[0].atoms[0].value == str(U_ALICE)
    assert "E301" in codes(compile_('allow [TRAVERSE] to user("zed");', resolver=DIRECTORY))


def test_symbolic_username_lint_mode_is_not_ssot_ready():
    res = compile_('allow [TRAVERSE] to user("alice");', allow_unresolved_usernames=True)
    assert res.ok and "W303" in codes(res) and res.policy.ssot_ready is False


@pytest.mark.parametrize(
    "ts",
    ["2026-12-01T00:00:00", "2026-12-01", "2026-12-01 00:00:00Z", "2026-13-01T00:00:00Z", "x"],
)
def test_naive_or_invalid_timestamps_rejected(ts):
    assert not compile_(f'allow [TRAVERSE] to any from "{ts}";').ok


def test_timestamp_normalised_to_utc():
    r = compile_('allow [TRAVERSE] to any from "2026-12-01T08:00:00+08:00";').policy.rules[0]
    assert r.valid_from == datetime(2026, 12, 1, tzinfo=UTC)


def test_empty_interval_error():
    both = 'from "2026-12-01T00:00:00Z" until "2026-12-01T08:00:00+08:00"'
    assert not compile_(f"allow [TRAVERSE] to any {both};").ok
    inv = 'from "2026-12-02T00:00:00Z" until "2026-12-01T00:00:00Z"'
    assert not compile_(f"allow [TRAVERSE] to any {inv};").ok


def test_expired_rule_is_warning_not_error():
    res = compile_('allow [TRAVERSE] to any until "2026-11-24T00:00:00Z";')
    assert res.ok and "W209" in codes(res)


def test_temporary_deny_warning():
    res = compile_('deny [TRAVERSE] to any until "2030-01-01T00:00:00Z";')
    assert res.ok and "W210" in codes(res)


# --- Canonical decompilation ---------------------------------------------------


def test_canonical_decompilation():
    src = f'''
    allow [PRESET_READ] to user("{U_BOB}"), group("a") remark "r";
    allow [WRITE_CONTENT, READ_CONTENT] on docs when group("a") and perm("p")
      from "2026-12-01T08:00:00+08:00";
    deny [PURGE] on self to any;
    '''
    text = decompile_policy(compile_(src).policy)
    lines = text.splitlines()
    assert lines[0] == "inherit on;"
    assert "on all" not in text
    assert "allow [TRAVERSE, LIST_DIRECTORY, READ_CONTENT, READ_METADATA] to " in text
    assert "allow [READ_CONTENT, WRITE_CONTENT] on docs when " in text
    assert 'from "2026-12-01T00:00:00Z"' in text
    assert "deny [PURGE] on self to any;" in text
    assert "PRESET" not in text
    # fixpoint
    assert decompile_policy(compile_(text).policy) == text


def test_decompile_roundtrip_examples():
    for src in (EXAMPLE_A, EXAMPLE_B, EXAMPLE_C):
        p = compile_(src, resolver=DIRECTORY).policy
        text = decompile_policy(p)
        assert "alice" not in text  # persisted as UUIDs
        assert compile_(text).policy.rules == p.rules  # stateless recompile


# --- Section 6 runtime ----------------------------------------------------------


def node(name, typ, src="", state=ObjectState.NORMAL):
    res = compile_(src) if src else compile_("inherit on;")
    assert res.ok, res.diagnostics
    return NamespaceNode(name, name, typ, state, res.policy)


D, F = ObjectType.DIRECTORY, ObjectType.DOCUMENT
ALICE = Subject(user_id=U_ALICE, groups=frozenset({"g"}), perms=frozenset({"p"}))
T = datetime(2026, 11, 24, tzinfo=UTC)


def ev(path, op, subj=ALICE, t=T, **kw):
    return evaluate_access(subj, path, op, t, **kw)


def test_default_deny_and_deny_overrides_order_independent():
    a = f'allow [READ_CONTENT] to user("{U_ALICE}");'
    d = 'deny [READ_CONTENT] to group("g");'
    for src in (a + d, d + a):
        assert not ev([node("f", F, src)], AtomicOp.READ_CONTENT, check_ancestor_traverse=False).allowed
    assert not ev([node("f", F)], AtomicOp.READ_CONTENT).allowed


def test_user_match_by_uuid():
    r = AtomicOp.READ_CONTENT
    kw = dict(check_ancestor_traverse=False)
    mine = node("f", F, f'allow [READ_CONTENT] to user("{str(U_ALICE).upper()}");')
    other = node("f", F, f'allow [READ_CONTENT] to user("{U_BOB}");')
    assert ev([mine], r, **kw).allowed
    assert not ev([other], r, **kw).allowed


def test_anonymous_never_matches_any():
    f = node("f", F, "allow [READ_CONTENT] to any;")
    assert ev([f], AtomicOp.READ_CONTENT).allowed
    assert not evaluate_access(None, [f], AtomicOp.READ_CONTENT, T).allowed


def test_scope_matrix_and_inherit_off():
    root = node("root", D, "allow [TRAVERSE, READ_CONTENT] on docs to any; allow [TRAVERSE] on self to any;")
    sub = node("sub", D, "allow [TRAVERSE] on dirs to any;")
    doc = node("doc", F)
    assert ev([root, sub, doc], AtomicOp.READ_CONTENT).allowed  # on docs, d>0
    assert ev([root, sub], AtomicOp.TRAVERSE, check_ancestor_traverse=False).allowed  # on dirs/self
    cut = node("cut", D, "inherit off;\nallow [TRAVERSE] on self to any;")
    assert not ev([root, cut, doc], AtomicOp.READ_CONTENT).allowed  # truncated


def test_inherit_off_retains_own_rules():
    root = node("root", D, "allow [TRAVERSE, READ_CONTENT] to any;")
    cut = node("cut", D, "inherit off; allow [TRAVERSE] to any;")
    doc = node("doc", F, "allow [READ_CONTENT] to any;")
    assert ev([root, cut, doc], AtomicOp.READ_CONTENT).allowed
    assert not ev([root, cut, node("d2", F)], AtomicOp.READ_CONTENT).allowed


def test_half_open_interval():
    f = node("f", F, 'allow [READ_CONTENT] to any from "2026-12-01T00:00:00Z" until "2026-12-02T00:00:00Z";')
    at = lambda s: datetime.fromisoformat(s)  # noqa: E731
    r = AtomicOp.READ_CONTENT
    kw = dict(check_ancestor_traverse=False)
    assert not ev([f], r, t=at("2026-11-30T23:59:59+00:00"), **kw).allowed
    assert ev([f], r, t=at("2026-12-01T00:00:00+00:00"), **kw).allowed
    assert not ev([f], r, t=at("2026-12-02T00:00:00+00:00"), **kw).allowed


def test_ancestor_traverse_required_and_bypassable():
    root = node("root", D)
    f = node("f", F, "allow [READ_CONTENT] to any;")
    assert not ev([root, f], AtomicOp.READ_CONTENT).allowed
    assert ev([root, f], AtomicOp.READ_CONTENT, check_ancestor_traverse=False).allowed
    root_t = node("root", D, "allow [TRAVERSE] to any;")
    assert ev([root_t, f], AtomicOp.READ_CONTENT).allowed


def test_trash_lifecycle_rules():
    allow_all = "allow [LIST_DELETED, RESTORE, PURGE, READ_CONTENT, DELETE] to any;"
    live = node("d", D, allow_all)
    dead = node("d", D, allow_all, ObjectState.SOFT_DELETED)
    assert not ev([dead], AtomicOp.READ_CONTENT).allowed
    assert not ev([dead], AtomicOp.DELETE).allowed
    assert ev([dead], AtomicOp.RESTORE).allowed and ev([dead], AtomicOp.PURGE).allowed
    assert ev([dead], AtomicOp.LIST_DELETED).allowed
    assert not ev([live], AtomicOp.RESTORE).allowed and not ev([live], AtomicOp.PURGE).allowed
    doc_dead = node("f", F, allow_all, ObjectState.SOFT_DELETED)
    assert not ev([doc_dead], AtomicOp.LIST_DELETED).allowed  # directories only


def test_trash_traverse_skips_soft_deleted_ancestors():
    allow = "allow [TRAVERSE, RESTORE, PURGE] to any;"
    root = node("root", D, allow)
    dead_dir = node("dd", D, allow, ObjectState.SOFT_DELETED)
    dead_doc = node("df", F, allow, ObjectState.SOFT_DELETED)
    assert ev([root, dead_dir, dead_doc], AtomicOp.PURGE).allowed
    # a soft-deleted dir cannot be restored under a soft-deleted parent
    assert not ev([root, dead_dir, node("dd2", D, allow, ObjectState.SOFT_DELETED)], AtomicOp.RESTORE).allowed
    assert ev([root, dead_dir], AtomicOp.RESTORE).allowed


def test_reparent_and_move_rename_composite():
    allow_src = 'allow [TRAVERSE, REPARENT] to any;'
    src = [node("s", D, allow_src), node("x", F, allow_src)]
    dst = [node("dst", D, "allow [TRAVERSE, CREATE_DOCUMENT] to any;")]
    assert evaluate_reparent(ALICE, src, dst, T).allowed
    assert not evaluate_reparent(ALICE, src, dst, T, also_rename=True).allowed  # needs RENAME
    both = 'allow [TRAVERSE, REPARENT, RENAME] to any;'
    src2 = [node("s", D, both), node("x", F, both)]
    assert evaluate_reparent(ALICE, src2, dst, T, also_rename=True).allowed
    dst_nocreate = [node("dst", D, "allow [TRAVERSE] to any;")]
    assert not evaluate_reparent(ALICE, src2, dst_nocreate, T).allowed


def test_soft_delete_non_empty_directory():
    base = "allow [TRAVERSE] to any;\n"
    target = [node("d", D, base + "allow [DELETE] to any;")]
    child = target + [node("c", F, "deny [DELETE] to any;")]
    assert not evaluate_soft_delete(ALICE, target, [child], T).allowed
    with_bypass = [node("d", D, base + "allow [DELETE, DIRECTORY_DELETE_CHILD] to any;")]
    child2 = with_bypass + [node("c", F, "deny [DELETE] to any;")]
    assert evaluate_soft_delete(ALICE, with_bypass, [child2], T).allowed
    # DIRECTORY_DELETE_CHILD alone never substitutes for DELETE on the target
    only_bypass = [node("d", D, base + "allow [DIRECTORY_DELETE_CHILD] to any;")]
    assert not evaluate_soft_delete(ALICE, only_bypass, [], T).allowed
