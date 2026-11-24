"""Conformance tests for CEP 2 (CACL) compiler, analyzer, IR, and decompiler."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cacl_compiler import (
    DEFAULT_PRESET_MACROS,
    AtomicOp,
    CompiledPolicy,
    CompiledRule,
    CompilerConfig,
    DecompileOptions,
    ObjectType,
    PredicateKind,
    collect_principal_refs,
    compile_cacl,
    decompile_policy,
    parse_cacl,
)
from cacl_compiler.ast_nodes import Effect, Scope
from cacl_compiler.cli import main as cli_main

GRAMMAR = Path(__file__).parents[1] / "src" / "cacl_compiler" / "cacl.lark"

EXAMPLE_A = """
inherit on;
# Prohibit reading or destroying historical revisions without audit clearance
deny [READ_REVISION, DELETE_REVISION] on docs
  when not perm("history_audit")
  remark "Prevent historical snapshot leakage and audit trail tampering";
allow [PRESET_RW, -RENAME, -DELETE]
  to user("5a52345a-ae51-4516-b277-bbd94b99d73a"), # external_bob
     group("external_editors")
  remark "External collaborators restricted to content iteration";
allow [PRESET_TRASH_RW] on dirs
  when (group("core_dev") and perm("vault_write")) or group("sec_auditors");
"""

EXAMPLE_B = """
inherit off;
allow [TRAVERSE, CREATE_DOCUMENT] on self
  to group("all_employees")
  remark "Blind dropbox submission entry point";
allow [LIST_DIRECTORY] on self
  to group("review_board");
allow [READ_CONTENT, READ_METADATA] on docs
  to group("review_board")
  remark "Read-only inspection by the review board";
"""

EXAMPLE_C = """
inherit on;
allow [PRESET_READ, LIST_REVISIONS] on docs
  to user("5548914a-1297-48f2-8c35-274d222f4338") # auditor_li
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
"""

NOW = datetime(2026, 11, 24, tzinfo=UTC)

# A user identifier is always a canonical 36-char RFC 9562 UUID.
U_ALICE = UUID("11111111-1111-4111-8111-111111111111")
U_BOB = UUID("5a52345a-ae51-4516-b277-bbd94b99d73a")
U_LI = UUID("5548914a-1297-48f2-8c35-274d222f4338")


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
        "PRESET_TRASH_RW", "PRESET_ACL_RW",
    }  # fmt: skip
    m = DEFAULT_PRESET_MACROS
    assert m["PRESET_RW"] == m["PRESET_READ"] | m["PRESET_WRITE"]
    assert m["PRESET_TRASH_RW"] == int(
        AtomicOp.LIST_DELETED
        | AtomicOp.RESTORE
        | AtomicOp.PURGE
        | AtomicOp.DIRECTORY_DELETE_CHILD
    )
    assert m["PRESET_ACL_RW"] == int(AtomicOp.READ_DACL | AtomicOp.WRITE_DACL)
    for excluded in (
        "READ_REVISION",
        "DELETE_REVISION",
        "PURGE",
        "READ_DACL",
        "WRITE_DACL",
    ):
        assert not m["PRESET_WRITE"] & AtomicOp[excluded]
    assert not compile_("allow [PRESET_EDIT] to any;").ok
    assert "E202" in codes(compile_("allow [PRESET_TRASH_MANAGE] to any;"))
    assert "E202" in codes(compile_("allow [PRESET_ACL_MANAGE] to any;"))


# --- Section 4: grammar -----------------------------------------------------


def test_grammar_matches_spec_text():
    text = GRAMMAR.read_text(encoding="utf-8")
    assert (
        'rule: effect op_set scope_clause? match_clause time_clause? remark_clause? ";"'
        in text
    )
    assert "start: directive* rule*" in text
    assert 'PRINCIPAL_KIND: "user" | "group"' in text


@pytest.mark.parametrize("src", [EXAMPLE_A, EXAMPLE_B, EXAMPLE_C])
def test_spec_examples_compile_statelessly(src):
    # All normative CEP 2 examples compile completely statelessly.
    res = compile_(src)
    assert res.ok, res.diagnostics
    assert not res.errors


def test_role_predicate_rejected():
    res = compile_('allow [TRAVERSE] to role("admin");')
    assert not res.ok and "E101" in codes(res)


def test_to_equals_when_or():
    a = compile_(f'allow [TRAVERSE] to user("{U_ALICE}"), group("g");').policy
    b = compile_(f'allow [TRAVERSE] when user("{U_ALICE}") or group("g");').policy
    assert a.rules[0].dnf_clauses == b.rules[0].dnf_clauses


def test_perm_not_allowed_in_to():
    assert not compile_('allow [TRAVERSE] to perm("x");').ok


def test_default_scope_all_and_inherit_on():
    p = compile_("allow [TRAVERSE] to any;").policy
    assert p.inherit is True and p.rules[0].scope is Scope.ALL


def test_precedence_not_and_or():
    # not > and > or  ==>  a or (b and (not c))
    r = compile_(
        'allow [TRAVERSE] when group("a") or group("b") and not group("c");'
    ).policy.rules[0]
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
    empty_res = compile_("allow [RENAME, -RENAME] on dirs to any;")
    assert "E203" in codes(empty_res)
    assert not (codes(empty_res) & {"W203", "W204"})


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
    res = compile_(
        "allow [PRESET_READ] on dirs to any;", target_object_type=ObjectType.DOCUMENT
    )
    assert "W205" in codes(res)


def test_predicate_literals():
    assert not compile_('allow [TRAVERSE] to user("");').ok
    assert not compile_('allow [TRAVERSE] to group("");').ok
    assert not compile_('allow [TRAVERSE] when perm("");').ok
    # group() and perm() are opaque non-empty strings without rigid charset restrictions
    assert compile_('allow [TRAVERSE] to group(" ");').ok
    assert compile_('allow [TRAVERSE] to group("core_dev:研发/1");').ok
    assert compile_('allow [TRAVERSE] when perm("vault.write:v2");').ok


@pytest.mark.parametrize(
    "bad_id",
    [
        "alice",
        "alice@example.com",
        "not-a-uuid",
        "1",
        "5a52345aae514516b277bbd94b99d73a",  # unhyphenated 32-hex
        "{5a52345a-ae51-4516-b277-bbd94b99d73a}",  # braced
        "urn:uuid:5a52345a-ae51-4516-b277-bbd94b99d73a",  # URN
        " 5a52345a-ae51-4516-b277-bbd94b99d73a",  # leading whitespace
        "5a52345a-ae51-4516-b277-bbd94b99d73a ",  # trailing whitespace
        "5a52345a-ae51-4516-b277-bbd94b99d73a\\n",  # escaped trailing newline
        "5a52345-aae51-4516-b277-bbd94b99d73a",  # wrong hyphen placement
        "5a52345g-ae51-4516-b277-bbd94b99d73a",  # non-hex char
    ],
)
def test_user_identifier_must_be_strict_rfc9562_uuid(bad_id):
    res = compile_(f'allow [TRAVERSE] to user("{bad_id}");')
    assert not res.ok and "E302" in codes(res)


@pytest.mark.parametrize(
    "valid_uuid",
    [
        "00000000-0000-0000-0000-000000000000",  # Nil UUID
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",  # Max UUID (uppercase)
        "12345678-1234-9ABC-0123-456789ABCDEF",  # Non-standard version/variant bits
        "5A52345A-AE51-4516-B277-BBD94B99D73A",  # Uppercase v4
    ],
)
def test_user_uuid_version_agnostic_and_canonicalised(valid_uuid):
    res = compile_(f'allow [TRAVERSE] to user("{valid_uuid}");')
    assert res.ok, res.diagnostics
    assert res.policy.rules[0].dnf_clauses[0].atoms[0].value == valid_uuid.lower()


def test_duplicate_user_uuid_case_variant_warns():
    res = compile_(
        f'allow [TRAVERSE] to user("{str(U_ALICE).upper()}"), user("{U_ALICE}");'
    )
    assert res.ok and "W208" in codes(res)


def test_collect_principal_refs_preserves_spans_and_normalizes_uuids():
    src = (
        f'allow [TRAVERSE] when user("{str(U_ALICE).upper()}") '
        'or (group("eng") and not perm("audit")) '
        'or user("not-a-uuid");'
    )
    ast, diags = parse_cacl(src)
    assert ast is not None and not diags
    refs = collect_principal_refs(ast)
    assert [(r.kind, r.value) for r in refs] == [
        (PredicateKind.USER, str(U_ALICE)),
        (PredicateKind.GROUP, "eng"),
        (PredicateKind.PERM, "audit"),
    ]
    assert all(r.span.line == 1 for r in refs)


@pytest.mark.parametrize(
    "ts",
    [
        "2026-12-01T00:00:00",
        "2026-12-01",
        "2026-12-01 00:00:00Z",
        "2026-13-01T00:00:00Z",
        "x",
    ],
)
def test_naive_or_invalid_timestamps_rejected(ts):
    assert not compile_(f'allow [TRAVERSE] to any from "{ts}";').ok


def test_timestamp_normalised_to_utc():
    r = compile_(
        'allow [TRAVERSE] to any from "2026-12-01T08:00:00+08:00";'
    ).policy.rules[0]
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
        p = compile_(src).policy
        text = decompile_policy(p)
        assert "external_bob" not in text and "auditor_li" not in text
        assert compile_(text).policy.rules == p.rules  # stateless recompile


def test_decompile_uuid_annotated_roundtrip():
    p = compile_(EXAMPLE_A).policy
    annotated = decompile_policy(
        p,
        DecompileOptions(user_annotations={str(U_BOB): "external_bob"}),
    )
    assert f'user("{U_BOB}")' in annotated
    assert "# @external_bob" in annotated
    assert compile_(annotated).policy.rules == p.rules


def test_cli_check_and_fmt_canonical(tmp_path: Path, capsys):
    policy_file = tmp_path / "example_a.cacl"
    policy_file.write_text(EXAMPLE_A, encoding="utf-8")
    assert cli_main(["check", str(policy_file)]) == 0
    assert cli_main(["fmt", str(policy_file)]) == 0
    out = capsys.readouterr().out
    assert f'user("{U_BOB}")' in out
    assert "PRESET_TRASH_RW" not in out  # canonical form expands macros

    bad_file = tmp_path / "legacy.cacl"
    bad_file.write_text(
        'allow [PRESET_TRASH_MANAGE] to user("alice");', encoding="utf-8"
    )
    assert cli_main(["check", str(bad_file)]) == 1


# --- IR Optimizations & Serialization ----------------------------------------


def test_dnf_minimization_tautology_resolution_and_absorption():
    # P or not P ==> tautology (any) with W213
    taut = compile_('allow [READ_CONTENT] when group("a") or not group("a");')
    assert taut.ok and "W213" in codes(taut)
    assert taut.policy.rules[0].is_unconditional

    # not (user(A) and user(B)) == not user(A) or not user(B) ==> tautology (user exclusivity)
    user_taut = compile_(
        f'allow [READ_CONTENT] when not (user("{U_ALICE}") and user("{U_BOB}"));'
    )
    assert user_taut.ok and "W213" in codes(user_taut)
    assert user_taut.policy.rules[0].is_unconditional

    # (a and p) or (a and not p) ==> a
    resolved = compile_(
        'allow [READ_CONTENT] when (group("a") and perm("p")) or (group("a") and not perm("p"));'
    )
    assert resolved.ok
    assert len(resolved.policy.rules[0].dnf_clauses) == 1
    assert len(resolved.policy.rules[0].dnf_clauses[0].atoms) == 1
    assert resolved.policy.rules[0].dnf_clauses[0].atoms[0].value == "a"

    # a or (not a and b) ==> a or b
    absorbed = compile_(
        'allow [READ_CONTENT] when group("a") or (not group("a") and group("b"));'
    )
    assert absorbed.ok
    sets = {
        frozenset((a.value, a.negated) for a in c.atoms)
        for c in absorbed.policy.rules[0].dnf_clauses
    }
    assert sets == {frozenset({("a", False)}), frozenset({("b", False)})}


def test_fingerprint_is_order_independent_and_canonicalize():
    src1 = f"""
    inherit on;
    allow [READ_CONTENT] to user("{U_ALICE}");
    deny [DELETE] to group("g") remark "no delete";
    """
    src2 = f"""
    inherit on;
    deny [DELETE] to group("g") remark "no delete";
    allow [READ_CONTENT] to user("{U_ALICE}");
    """
    p1 = compile_(src1).policy
    p2 = compile_(src2).policy
    assert p1.fingerprint() == p2.fingerprint()
    assert p1.canonicalize() == p2.canonicalize()
    assert p1.fingerprint(include_remarks=False) == p2.fingerprint(
        include_remarks=False
    )

    src3 = f"""
    inherit on;
    allow [READ_CONTENT] to user("{U_ALICE}");
    deny [DELETE] to group("g") remark "different remark";
    """
    p3 = compile_(src3).policy
    assert p1.fingerprint(include_remarks=True) != p3.fingerprint(include_remarks=True)
    assert p1.fingerprint(include_remarks=False) == p3.fingerprint(
        include_remarks=False
    )


def test_policy_dict_roundtrip():
    p = compile_(EXAMPLE_C).policy
    restored = CompiledPolicy.from_dict(p.to_dict())
    assert restored == p
    assert restored.fingerprint() == p.fingerprint()


def test_compiled_rule_validates_invariants():
    with pytest.raises(ValueError, match="permission_mask"):
        CompiledRule(Effect.ALLOW, 0, Scope.ALL, (), None, None, None)
    with pytest.raises(ValueError, match="timezone-aware"):
        CompiledRule(
            Effect.ALLOW,
            int(AtomicOp.TRAVERSE),
            Scope.ALL,
            (),
            datetime(2026, 1, 1),
            None,
            None,
        )
    with pytest.raises(ValueError, match="strictly earlier"):
        CompiledRule(
            Effect.ALLOW,
            int(AtomicOp.TRAVERSE),
            Scope.ALL,
            (),
            datetime(2026, 1, 2, tzinfo=UTC),
            datetime(2026, 1, 1, tzinfo=UTC),
            None,
        )
