import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { fileTests } from "@lezer/generator/test";
import { parser } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const casesDir = path.join(__dirname, "cases");

describe("Lezer CACL grammar", () => {
  for (const file of fs.readdirSync(casesDir)) {
    if (!file.endsWith(".txt")) continue;
    const content = fs.readFileSync(path.join(casesDir, file), "utf8");
    for (const { name, run } of fileTests(content, file)) {
      it(name, () => {
        run(parser);
      });
    }
  }

  it("recovers from syntax errors in one rule and still parses subsequent rules", () => {
    const src = "allow [TRAVERSE] to ;\nallow [READ_CONTENT] on docs to any;\n";
    const tree = parser.parse(src);
    let ruleCount = 0;
    let errorCount = 0;
    const cur = tree.cursor();
    do {
      if (cur.name === "Rule") ruleCount++;
      if (cur.type.isError) errorCount++;
    } while (cur.next());
    assert.ok(errorCount >= 1);
    assert.equal(ruleCount, 2);
  });
});
