import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { defaultHighlightStyle } from "@codemirror/language";
import { highlightTree, tagHighlighter, tags as t } from "@lezer/highlight";
import { parser } from "../dist/index.js";

function collectHighlights(source) {
  const tree = parser.parse(source);
  const tokens = [];
  const highlighter = tagHighlighter([
    { tag: t.controlKeyword, class: "tok-ctrl" },
    { tag: t.definitionKeyword, class: "tok-def" },
    { tag: t.keyword, class: "tok-kw" },
    { tag: t.bool, class: "tok-bool" },
    { tag: t.typeName, class: "tok-type" },
    { tag: t.operatorKeyword, class: "tok-opkw" },
    { tag: t.atom, class: "tok-atom" },
    { tag: t.function(t.variableName), class: "tok-fn" },
    { tag: t.macroName, class: "tok-macro" },
    { tag: t.constant(t.name), class: "tok-const" },
    { tag: t.variableName, class: "tok-var" },
    { tag: t.arithmeticOperator, class: "tok-arith" },
    { tag: t.special(t.string), class: "tok-ts" },
    { tag: t.string, class: "tok-str" },
    { tag: t.lineComment, class: "tok-comment" },
    { tag: t.squareBracket, class: "tok-brack" },
    { tag: t.paren, class: "tok-paren" },
    { tag: t.separator, class: "tok-sep" },
  ]);

  highlightTree(tree, highlighter, (from, to, classes) => {
    tokens.push({ text: source.slice(from, to), classes });
  });
  return tokens;
}

describe("CACL semantic highlighting", () => {
  it("highlights all CACL syntactic categories with distinct tags", () => {
    const src = [
      "# header",
      "inherit on;",
      'allow [PRESET_RW, -DELETE, UNKNOWN_OP] on docs when not perm("audit") or any',
      '  from "2026-01-01T00:00:00Z" remark "note";',
    ].join("\n");

    const tokens = collectHighlights(src);
    const byText = new Map(tokens.map((tok) => [tok.text, tok.classes]));
    const onTokens = tokens.filter((tok) => tok.text === "on").map((tok) => tok.classes);

    assert.equal(byText.get("# header"), "tok-comment");
    assert.equal(byText.get("inherit"), "tok-def");
    assert.deepEqual(onTokens, ["tok-bool", "tok-kw"]);
    assert.equal(byText.get("allow"), "tok-ctrl");
    assert.equal(byText.get("PRESET_RW"), "tok-macro");
    assert.equal(byText.get("-"), "tok-arith");
    assert.equal(byText.get("DELETE"), "tok-const");
    assert.equal(byText.get("UNKNOWN_OP"), "tok-var");
    assert.equal(byText.get("docs"), "tok-type");
    assert.equal(byText.get("when"), "tok-ctrl");
    assert.equal(byText.get("not"), "tok-opkw");
    assert.equal(byText.get("perm"), "tok-fn");
    assert.equal(byText.get('"audit"'), "tok-str");
    assert.equal(byText.get("or"), "tok-opkw");
    assert.equal(byText.get("any"), "tok-atom");
    assert.equal(byText.get("from"), "tok-kw");
    assert.equal(byText.get('"2026-01-01T00:00:00Z"'), "tok-ts");
    assert.equal(byText.get("remark"), "tok-kw");
    assert.equal(byText.get('"note"'), "tok-str");
  });

  it("works cleanly with CodeMirror defaultHighlightStyle", () => {
    const src = 'deny [PURGE] on all to user("550e8400-e29b-41d4-a716-446655440000");';
    const tree = parser.parse(src);
    let styledCount = 0;
    highlightTree(tree, defaultHighlightStyle, () => {
      styledCount++;
    });
    assert.ok(styledCount > 0);
  });
});
