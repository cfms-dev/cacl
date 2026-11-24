import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { analyzeCacl, DEFAULT_PRESET_MACROS } from "../dist/index.js";

const NOW = new Date("2026-11-24T00:00:00Z");
const U_ALICE = "11111111-1111-4111-8111-111111111111";
const U_BOB = "5a52345a-ae51-4516-b277-bbd94b99d73a";

const EXAMPLE_A = `
inherit on;
# Prohibit reading or destroying historical revisions without audit clearance
deny [READ_REVISION, DELETE_REVISION] on docs
  when not perm("history_audit")
  remark "Prevent historical snapshot leakage and audit trail tampering";
allow [PRESET_RW, -RENAME, -DELETE]
  to user("${U_BOB}"), # external_bob
     group("external_editors")
  remark "External collaborators restricted to content iteration";
allow [PRESET_TRASH_RW] on dirs
  when (group("core_dev") and perm("vault_write")) or group("sec_auditors");
`;

const EXAMPLE_B = `
inherit off;
allow [TRAVERSE, CREATE_DOCUMENT] on self
  to group("all_employees")
  remark "Blind dropbox submission entry point";
allow [LIST_DIRECTORY] on self
  to group("review_board");
allow [READ_CONTENT, READ_METADATA] on docs
  to group("review_board")
  remark "Read-only inspection by the review board";
`;

const EXAMPLE_C = `
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
`;

function codes(res) {
  return new Set(res.diagnostics.map((d) => d.code));
}

describe("CACL static analyzer", () => {
  it("compiles CEP 2 normative examples with zero errors", () => {
    for (const src of [EXAMPLE_A, EXAMPLE_B]) {
      const res = analyzeCacl(src, { nowUtc: NOW });
      assert.equal(res.ok, true);
      assert.equal(res.diagnostics.length, 0);
    }
    const resC = analyzeCacl(EXAMPLE_C, { nowUtc: NOW });
    assert.equal(resC.ok, true);
    assert.deepEqual([...codes(resC)], ["W210"]);
  });

  it("reports E101 on syntax errors and E102 on invalid string escapes", () => {
    const syn = analyzeCacl("allow [TRAVERSE] to", { nowUtc: NOW });
    assert.equal(syn.ok, false);
    assert.ok(codes(syn).has("E101"));

    const roleErr = analyzeCacl('allow [TRAVERSE] to role("admin");', { nowUtc: NOW });
    assert.equal(roleErr.ok, false);
    assert.ok(codes(roleErr).has("E101"));

    const esc = analyzeCacl('allow [TRAVERSE] to group("bad\\q");', { nowUtc: NOW });
    assert.equal(esc.ok, false);
    assert.ok(codes(esc).has("E102"));
    const e102 = esc.diagnostics.find((d) => d.code === "E102");
    assert.equal(esc.diagnostics.length > 0, true);
    assert.equal('allow [TRAVERSE] to group("bad\\q");'.slice(e102.from, e102.to), "\\q");
  });

  it("reports E201 on duplicate inherit directives", () => {
    const res = analyzeCacl("inherit on;\ninherit off;\nallow [TRAVERSE] to any;", { nowUtc: NOW });
    assert.equal(res.ok, false);
    assert.ok(codes(res).has("E201"));
  });

  it("validates operation algebra (E202, E203, E210, W201, W202)", () => {
    const unknown = analyzeCacl("allow [PRESET_EDIT] to any;", { nowUtc: NOW });
    assert.ok(codes(unknown).has("E202"));

    const negLead = analyzeCacl("allow [-TRAVERSE, READ_CONTENT] to any;", { nowUtc: NOW });
    assert.ok(codes(negLead).has("E210"));

    const emptyMask = analyzeCacl("allow [TRAVERSE, -TRAVERSE] to any;", { nowUtc: NOW });
    assert.ok(codes(emptyMask).has("E203"));

    const ineffectiveSub = analyzeCacl("allow [TRAVERSE, -DELETE] to any;", { nowUtc: NOW });
    assert.ok(codes(ineffectiveSub).has("W201"));

    const redundantAdd = analyzeCacl("allow [PRESET_READ, TRAVERSE] to any;", { nowUtc: NOW });
    assert.ok(codes(redundantAdd).has("W202"));

    const customMacro = analyzeCacl("allow [CUSTOM_READ] to any;", {
      nowUtc: NOW,
      macros: { ...DEFAULT_PRESET_MACROS, CUSTOM_READ: 1 },
    });
    assert.equal(customMacro.ok, true);
    assert.equal(customMacro.diagnostics.length, 0);
  });

  it("validates scope compatibility (W203, W204, W205)", () => {
    const w203 = analyzeCacl("allow [TRAVERSE] on docs to any;", { nowUtc: NOW });
    assert.ok(codes(w203).has("W203"));

    const w204 = analyzeCacl("allow [READ_CONTENT] on dirs to any;", { nowUtc: NOW });
    assert.ok(codes(w204).has("W204"));
    const d204 = w204.diagnostics.find((d) => d.code === "W204");
    assert.equal("allow [READ_CONTENT] on dirs to any;".slice(d204.from, d204.to), "dirs");

    const w205DocDirs = analyzeCacl("allow [READ_METADATA] on dirs to any;", {
      nowUtc: NOW,
      targetObjectType: "document",
    });
    assert.ok(codes(w205DocDirs).has("W205"));

    const w205DocSelf = analyzeCacl("allow [TRAVERSE] on self to any;", {
      nowUtc: NOW,
      targetObjectType: "document",
    });
    assert.ok(codes(w205DocSelf).has("W205"));

    const w205DirSelf = analyzeCacl("allow [READ_CONTENT] on self to any;", {
      nowUtc: NOW,
      targetObjectType: "directory",
    });
    assert.ok(codes(w205DirSelf).has("W205"));
  });

  it("validates predicates, UUIDs, and boolean DNF logic (E204, E205, E208, E302, W206, W207, W208, W213)", () => {
    assert.ok(codes(analyzeCacl('allow [TRAVERSE] to group("");', { nowUtc: NOW })).has("E204"));
    assert.ok(codes(analyzeCacl('allow [TRAVERSE] to perm("x");', { nowUtc: NOW })).has("E205"));
    assert.ok(codes(analyzeCacl('allow [TRAVERSE] to user("alice");', { nowUtc: NOW })).has("E302"));

    // W208: duplicate principal (case-insensitive UUID)
    const dupTo = analyzeCacl(
      `allow [TRAVERSE] to user("${U_ALICE.toUpperCase()}"), user("${U_ALICE}");`,
      { nowUtc: NOW },
    );
    assert.ok(codes(dupTo).has("W208"));

    // W206: user exclusivity contradiction
    const deadUser = analyzeCacl(
      `allow [TRAVERSE] when user("${U_ALICE}") and user("${U_BOB}");`,
      { nowUtc: NOW },
    );
    assert.ok(codes(deadUser).has("W206"));

    // W207: absorbed by any
    const anyOr = analyzeCacl('allow [TRAVERSE] when any or group("devs");', { nowUtc: NOW });
    assert.ok(codes(anyOr).has("W207"));

    // W213: tautology via user-exclusivity or P or not P
    const taut = analyzeCacl('allow [TRAVERSE] when group("a") or not group("a");', { nowUtc: NOW });
    assert.ok(codes(taut).has("W213"));

    const userTaut = analyzeCacl(
      `allow [TRAVERSE] when not user("${U_ALICE}") or not user("${U_BOB}");`,
      { nowUtc: NOW },
    );
    assert.ok(codes(userTaut).has("W213"));

    // E208: DNF blowup
    const pairs = Array.from({ length: 9 }, (_, i) => `(group("a${i}") or group("b${i}"))`).join(" and ");
    const blowup = analyzeCacl(`allow [TRAVERSE] when ${pairs};`, { nowUtc: NOW });
    assert.ok(codes(blowup).has("E208"));
  });

  it("validates RFC 3339 timestamps and time windows (E206, E207, W209, W210)", () => {
    // Missing tz
    assert.ok(
      codes(analyzeCacl('allow [TRAVERSE] to any from "2026-12-01T00:00:00";', { nowUtc: NOW })).has("E206"),
    );
    // Invalid calendar date (Feb 30)
    assert.ok(
      codes(analyzeCacl('allow [TRAVERSE] to any from "2026-02-30T00:00:00Z";', { nowUtc: NOW })).has("E206"),
    );
    // Inverted window
    assert.ok(
      codes(
        analyzeCacl(
          'allow [TRAVERSE] to any from "2026-12-10T00:00:00Z" until "2026-12-10T00:00:00Z";',
          { nowUtc: NOW },
        ),
      ).has("E207"),
    );
    // Expired (W209) + temporary deny (W210)
    const expDeny = analyzeCacl('deny [TRAVERSE] to any until "2026-11-23T00:00:00Z";', {
      nowUtc: NOW,
    });
    assert.ok(codes(expDeny).has("W209"));
    assert.ok(codes(expDeny).has("W210"));
  });

  it("detects cross-rule duplicates (W211) and global deny shadowing (W212)", () => {
    const dup = analyzeCacl(
      'allow [TRAVERSE] to group("devs");\nallow [TRAVERSE] when group("devs") remark "dup";',
      { nowUtc: NOW },
    );
    assert.ok(codes(dup).has("W211"));

    const shadowed = analyzeCacl(
      'deny [DELETE] on all to any;\nallow [READ_CONTENT, DELETE] to group("devs");',
      { nowUtc: NOW },
    );
    assert.ok(codes(shadowed).has("W212"));
  });

  it("respects includeWarnings: false", () => {
    const res = analyzeCacl("allow [PRESET_READ, TRAVERSE] to any;", {
      nowUtc: NOW,
      includeWarnings: false,
    });
    assert.equal(res.ok, true);
    assert.equal(res.diagnostics.length, 0);
  });
});
