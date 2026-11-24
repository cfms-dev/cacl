import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { describe, it } from "node:test";
import { CompletionContext } from "@codemirror/autocomplete";
import { syntaxTree } from "@codemirror/language";
import { EditorState } from "@codemirror/state";
import {
  analyzeCacl,
  cacl,
  caclCompletionSource,
  caclLanguage,
  toCodeMirrorDiagnostics,
} from "../dist/index.js";

const require = createRequire(import.meta.url);

describe("CodeMirror 6 CACL integration", () => {
  it("supports EditorState creation, cacl() LanguageSupport, and CJS bundle import", () => {
    const doc = 'inherit on;\nallow [PRESET_READ] on docs to group("editors");\n';
    const state = EditorState.create({
      doc,
      extensions: [cacl()],
    });
    const tree = syntaxTree(state);
    assert.equal(tree.topNode.name, "Policy");
    assert.equal(state.facet(caclLanguage.data).length > 0, true);

    const cjs = require("../dist/index.cjs");
    assert.equal(typeof cjs.cacl, "function");
    assert.equal(cjs.analyzeCacl(doc).ok, true);
  });

  it("generates Quick Fix actions and applies them cleanly", () => {
    // E202 close match fix
    const typoDoc = "allow [TRAVERS] to any;\n";
    const typoDiags = toCodeMirrorDiagnostics(typoDoc, analyzeCacl(typoDoc));
    const e202 = typoDiags.find((d) => d.message.includes("[E202]"));
    assert.ok(e202?.actions?.length);
    const fixAction = e202.actions.find((a) => a.name === "Use 'TRAVERSE'");
    assert.ok(fixAction);

    let state = EditorState.create({ doc: typoDoc });
    fixAction.apply(
      {
        state,
        dispatch(tr) {
          state = state.update(tr).state;
        },
      },
      e202.from,
      e202.to,
    );
    assert.equal(state.doc.toString(), "allow [TRAVERSE] to any;\n");

    // W202 redundant op removal fix
    const dupOpDoc = "allow [PRESET_READ, TRAVERSE] to any;\n";
    const dupOpDiags = toCodeMirrorDiagnostics(dupOpDoc, analyzeCacl(dupOpDoc));
    const w202 = dupOpDiags.find((d) => d.message.includes("[W202]"));
    assert.ok(w202?.actions?.length);
    let opState = EditorState.create({ doc: dupOpDoc });
    w202.actions[0].apply(
      {
        state: opState,
        dispatch(tr) {
          opState = opState.update(tr).state;
        },
      },
      w202.from,
      w202.to,
    );
    assert.equal(opState.doc.toString(), "allow [PRESET_READ] to any;\n");

    // E205 convert `to` to `when` fix
    const toPermDoc = 'allow [TRAVERSE] to perm("audit");\n';
    const toPermDiags = toCodeMirrorDiagnostics(toPermDoc, analyzeCacl(toPermDoc));
    const e205 = toPermDiags.find((d) => d.message.includes("[E205]"));
    assert.ok(e205?.actions?.length);
    let permState = EditorState.create({ doc: toPermDoc });
    e205.actions[0].apply(
      {
        state: permState,
        dispatch(tr) {
          permState = permState.update(tr).state;
        },
      },
      e205.from,
      e205.to,
    );
    assert.equal(permState.doc.toString(), 'allow [TRAVERSE] when perm("audit");\n');
  });

  it("provides context-aware autocompletion in OpSet, Scope, and when clauses", () => {
    const opDoc = "allow [PRES";
    const opState = EditorState.create({ doc: opDoc, extensions: [cacl({ lint: false })] });
    const opRes = caclCompletionSource(new CompletionContext(opState, opDoc.length, true));
    assert.ok(opRes?.options.some((o) => o.label === "PRESET_RW"));

    const scopeDoc = "allow [TRAVERSE] on d";
    const scopeState = EditorState.create({ doc: scopeDoc, extensions: [cacl({ lint: false })] });
    const scopeRes = caclCompletionSource(new CompletionContext(scopeState, scopeDoc.length, true));
    assert.ok(scopeRes?.options.some((o) => o.label === "dirs"));
    assert.ok(scopeRes?.options.some((o) => o.label === "docs"));

    const commentDoc = "# allow [";
    const commentState = EditorState.create({ doc: commentDoc, extensions: [cacl({ lint: false })] });
    const commentRes = caclCompletionSource(
      new CompletionContext(commentState, commentDoc.length, true),
    );
    assert.equal(commentRes, null);
  });
});
