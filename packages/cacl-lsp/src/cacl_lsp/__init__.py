import argparse
import logging
import sys

from .server import CaclLanguageServer, create_server, get_server_version

__all__ = ["CaclLanguageServer", "create_server", "get_server_version", "main"]


def _configure_logging(log_file: str | None, log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    handlers: list[logging.Handler] = []
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    else:
        # Never write logs to stdout because stdio JSON-RPC framing uses stdout.
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cacl-lsp",
        description="Language Server Protocol (LSP) server for CACL (CEP 2).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_server_version()}",
    )
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Communicate over standard input/output (default).",
    )
    transport.add_argument(
        "--tcp",
        action="store_true",
        help="Listen on a TCP socket instead of stdio.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="TCP bind host when --tcp is set (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2087,
        help="TCP bind port when --tcp is set (default: 2087).",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional path to write diagnostic server logs.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Server logging verbosity (default: WARNING).",
    )

    args = parser.parse_args(argv)
    _configure_logging(args.log_file, args.log_level)

    server = create_server()
    if args.tcp:
        server.start_tcp(args.host, args.port)
    else:
        server.start_io()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
