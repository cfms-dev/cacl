import * as vscode from "vscode";
import {
  LanguageClient,
  type LanguageClientOptions,
  type ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";
import { resolveServerLaunch } from "./serverLauncher";

let client: LanguageClient | undefined;
let outputChannel: vscode.LogOutputChannel | undefined;

async function startClient(context: vscode.ExtensionContext): Promise<void> {
  const config = vscode.workspace.getConfiguration("cacl");
  const configuredCommand = config.get<string>("server.command", "");
  const configuredArgs = config.get<string[]>("server.args", []);
  const workspaceFolders = (vscode.workspace.workspaceFolders ?? []).map(
    (folder) => folder.uri.fsPath
  );

  const launch = resolveServerLaunch({
    configuredCommand,
    configuredArgs,
    workspaceFolders,
  });

  if (!launch) {
    const action = await vscode.window.showErrorMessage(
      "Unable to locate the `cacl-lsp` language server. Install `cacl-lsp` in your workspace `.venv`, add it to PATH, or set `cacl.server.command`.",
      "Open Settings"
    );
    if (action === "Open Settings") {
      await vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "cacl.server.command"
      );
    }
    return;
  }

  outputChannel ??= vscode.window.createOutputChannel("CACL Language Server", {
    log: true,
  });
  outputChannel.info(
    `Starting cacl-lsp (${launch.source}): ${launch.command} ${launch.args.join(" ")}`
  );

  const serverOptions: ServerOptions = {
    command: launch.command,
    args: launch.args,
    transport: TransportKind.stdio,
    options: launch.cwd ? { cwd: launch.cwd } : undefined,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "cacl" },
      { scheme: "untitled", language: "cacl" },
    ],
    synchronize: {
      configurationSection: "cacl",
    },
    outputChannel,
    traceOutputChannel: outputChannel,
  };

  client = new LanguageClient(
    "cacl",
    "CACL Language Server",
    serverOptions,
    clientOptions
  );

  await client.start();
}

async function stopClient(): Promise<void> {
  if (!client) {
    return;
  }
  const active = client;
  client = undefined;
  await active.stop();
}

async function restartClient(context: vscode.ExtensionContext): Promise<void> {
  outputChannel?.info("Restarting CACL Language Server...");
  await stopClient();
  await startClient(context);
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  outputChannel = vscode.window.createOutputChannel("CACL Language Server", {
    log: true,
  });
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("cacl.restartServer", async () => {
      await restartClient(context);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (
        event.affectsConfiguration("cacl.server.command") ||
        event.affectsConfiguration("cacl.server.args")
      ) {
        await restartClient(context);
      }
    })
  );

  await startClient(context);
}

export async function deactivate(): Promise<void> {
  await stopClient();
}
