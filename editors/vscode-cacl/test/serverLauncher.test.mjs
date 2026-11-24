import test from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { resolveServerLaunch } from "../src/serverLauncher.ts";

test("uses explicit cacl.server.command with workspaceFolder expansion", () => {
  const res = resolveServerLaunch({
    configuredCommand: "${workspaceFolder}/custom/cacl-lsp",
    configuredArgs: ["--log-level", "DEBUG"],
    workspaceFolders: ["D:\\projects\\cacl"],
    platform: "win32",
    envPath: "",
    fileExists: () => false,
  });
  assert.ok(res);
  assert.equal(res.source, "configured");
  assert.equal(res.command, "D:\\projects\\cacl/custom/cacl-lsp");
  assert.deepEqual(res.args, ["--log-level", "DEBUG"]);
});

test("auto-detects .venv in parent monorepo root on Windows", () => {
  const expectedExe = path.resolve("D:\\projects\\cacl", ".venv", "Scripts", "cacl-lsp.exe");
  const res = resolveServerLaunch({
    configuredCommand: "",
    configuredArgs: [],
    workspaceFolders: ["D:\\projects\\cacl\\editors\\vscode-cacl"],
    platform: "win32",
    envPath: "",
    fileExists: (p) => path.resolve(p) === expectedExe,
  });
  assert.ok(res);
  assert.equal(res.source, "venv");
  assert.equal(path.resolve(res.command), expectedExe);
  assert.deepEqual(res.args, ["--stdio"]);
});

test("falls back to PATH cacl-lsp and then uv run cacl-lsp", () => {
  const pathHit = resolveServerLaunch({
    configuredCommand: "",
    configuredArgs: [],
    workspaceFolders: ["/repo"],
    platform: "linux",
    envPath: "/usr/local/bin:/usr/bin",
    fileExists: (p) => p === path.join("/usr/local/bin", "cacl-lsp"),
  });
  assert.ok(pathHit);
  assert.equal(pathHit.source, "path");
  assert.equal(pathHit.command, path.join("/usr/local/bin", "cacl-lsp"));

  const uvHit = resolveServerLaunch({
    configuredCommand: "",
    configuredArgs: ["--log-level", "INFO"],
    workspaceFolders: ["/repo"],
    platform: "linux",
    envPath: "/usr/local/bin",
    fileExists: (p) => p === path.join("/usr/local/bin", "uv"),
  });
  assert.ok(uvHit);
  assert.equal(uvHit.source, "uv");
  assert.deepEqual(uvHit.args, ["run", "cacl-lsp", "--stdio", "--log-level", "INFO"]);
});

test("returns undefined when no executable is available", () => {
  const res = resolveServerLaunch({
    configuredCommand: "",
    configuredArgs: [],
    workspaceFolders: ["/repo"],
    platform: "linux",
    envPath: "/usr/bin",
    fileExists: () => false,
  });
  assert.equal(res, undefined);
});
