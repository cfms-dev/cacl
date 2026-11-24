import * as fs from "node:fs";
import * as path from "node:path";

export interface ServerLaunchSpec {
  command: string;
  args: string[];
  cwd?: string;
  source: "configured" | "venv" | "path" | "uv";
}

export interface ServerResolveInput {
  configuredCommand: string;
  configuredArgs: string[];
  workspaceFolders: string[];
  platform?: NodeJS.Platform;
  envPath?: string;
  fileExists?: (filePath: string) => boolean;
}

function defaultFileExists(filePath: string): boolean {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function expandWorkspaceVar(value: string, primaryWorkspace?: string): string {
  if (!primaryWorkspace) {
    return value;
  }
  return value.replace(/\$\{workspaceFolder\}/g, primaryWorkspace);
}

function findExecutableOnPath(
  names: string[],
  envPath: string,
  platform: NodeJS.Platform,
  fileExists: (p: string) => boolean
): string | undefined {
  const sep = platform === "win32" ? ";" : ":";
  const dirs = envPath.split(sep).filter(Boolean);
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (fileExists(candidate)) {
        return candidate;
      }
    }
  }
  return undefined;
}

function findVenvExecutable(
  workspaceFolders: string[],
  platform: NodeJS.Platform,
  fileExists: (p: string) => boolean
): { executable: string; rootDir: string } | undefined {
  const relCandidates =
    platform === "win32"
      ? [path.join(".venv", "Scripts", "cacl-lsp.exe")]
      : [path.join(".venv", "bin", "cacl-lsp")];

  const visited = new Set<string>();

  for (const folder of workspaceFolders) {
    let current = path.resolve(folder);
    for (let depth = 0; depth < 5; depth++) {
      if (visited.has(current)) {
        break;
      }
      visited.add(current);

      for (const rel of relCandidates) {
        const candidate = path.join(current, rel);
        if (fileExists(candidate)) {
          return { executable: candidate, rootDir: current };
        }
      }

      const parent = path.dirname(current);
      if (parent === current) {
        break;
      }
      current = parent;
    }
  }

  return undefined;
}

/**
 * Resolve how to launch `cacl-lsp`:
 * 1. Explicit `cacl.server.command` (+ `cacl.server.args`).
 * 2. Local `.venv` inside workspace folders (or up to 4 parent directories for monorepos).
 * 3. `cacl-lsp` installed on `PATH`.
 * 4. Fallback to `uv run cacl-lsp` when `uv` is available on `PATH`.
 */
export function resolveServerLaunch(input: ServerResolveInput): ServerLaunchSpec | undefined {
  const platform = input.platform ?? process.platform;
  const envPath = input.envPath ?? process.env.PATH ?? "";
  const fileExists = input.fileExists ?? defaultFileExists;
  const primaryWorkspace = input.workspaceFolders[0];
  const extraArgs = input.configuredArgs.map((arg) =>
    expandWorkspaceVar(arg, primaryWorkspace)
  );

  // 1. Explicit user-configured command
  const trimmedCmd = input.configuredCommand.trim();
  if (trimmedCmd.length > 0) {
    return {
      command: expandWorkspaceVar(trimmedCmd, primaryWorkspace),
      args: extraArgs,
      cwd: primaryWorkspace,
      source: "configured",
    };
  }

  // 2. Auto-detect workspace .venv
  const venvHit = findVenvExecutable(input.workspaceFolders, platform, fileExists);
  if (venvHit) {
    return {
      command: venvHit.executable,
      args: ["--stdio", ...extraArgs],
      cwd: venvHit.rootDir,
      source: "venv",
    };
  }

  // 3. `cacl-lsp` on PATH
  const lspNames = platform === "win32" ? ["cacl-lsp.exe", "cacl-lsp.cmd", "cacl-lsp"] : ["cacl-lsp"];
  const pathLsp = findExecutableOnPath(lspNames, envPath, platform, fileExists);
  if (pathLsp) {
    return {
      command: pathLsp,
      args: ["--stdio", ...extraArgs],
      cwd: primaryWorkspace,
      source: "path",
    };
  }

  // 4. Fallback to `uv run cacl-lsp`
  const uvNames = platform === "win32" ? ["uv.exe", "uv.cmd", "uv"] : ["uv"];
  const pathUv = findExecutableOnPath(uvNames, envPath, platform, fileExists);
  if (pathUv) {
    return {
      command: pathUv,
      args: ["run", "cacl-lsp", "--stdio", ...extraArgs],
      cwd: primaryWorkspace,
      source: "uv",
    };
  }

  return undefined;
}
