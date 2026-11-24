import json
import subprocess
import sys
from typing import Any


def _encode_lsp(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def _read_lsp_message(stream) -> dict[str, Any]:
    headers: dict[str, str] = {}
    while True:
        raw_line = stream.readline()
        if not raw_line:
            raise EOFError("Unexpected EOF while reading LSP headers")
        line = raw_line.decode("ascii").strip()
        if not line:
            break
        key, _, val = line.partition(":")
        headers[key.strip().lower()] = val.strip()
    content_length = int(headers["content-length"])
    body = stream.read(content_length)
    return json.loads(body.decode("utf-8"))


def test_stdio_end_to_end_session():
    proc = subprocess.Popen(
        [sys.executable, "-m", "cacl_lsp", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None

    try:
        # 1. initialize
        proc.stdin.write(
            _encode_lsp({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"processId": None, "rootUri": None, "capabilities": {}},
            })
        )
        proc.stdin.flush()

        init_resp = _read_lsp_message(proc.stdout)
        assert init_resp["id"] == 1
        caps = init_resp["result"]["capabilities"]
        assert caps["hoverProvider"] is True
        assert caps["documentFormattingProvider"] is True
        assert caps["semanticTokensProvider"]["full"] is True

        # 2. initialized + didOpen
        proc.stdin.write(
            _encode_lsp({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        )
        uri = "file:///e2e.cacl"
        proc.stdin.write(
            _encode_lsp({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "cacl",
                        "version": 1,
                        "text": 'inherit on;\nallow [PRESET_READ, BOGUS_OP] to any;\n',
                    }
                },
            })
        )
        proc.stdin.flush()

        # Expect publishDiagnostics notification containing E202
        diag_msg = _read_lsp_message(proc.stdout)
        assert diag_msg["method"] == "textDocument/publishDiagnostics"
        assert any(d["code"] == "E202" for d in diag_msg["params"]["diagnostics"])

        # 3. hover on PRESET_READ
        proc.stdin.write(
            _encode_lsp({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": {"uri": uri},
                    "position": {"line": 1, "character": 9},
                },
            })
        )
        proc.stdin.flush()

        hover_resp = _read_lsp_message(proc.stdout)
        assert hover_resp["id"] == 2
        assert "PRESET_READ" in hover_resp["result"]["contents"]["value"]

        # 4. shutdown & exit
        proc.stdin.write(
            _encode_lsp({"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": None})
        )
        proc.stdin.flush()
        shutdown_resp = _read_lsp_message(proc.stdout)
        assert shutdown_resp["id"] == 3

        proc.stdin.write(_encode_lsp({"jsonrpc": "2.0", "method": "exit", "params": None}))
        proc.stdin.flush()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
