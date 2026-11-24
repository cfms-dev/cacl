import argparse
import json
import sys
from pathlib import Path

from .analyzer import CompilerConfig, compile_cacl
from .decompiler import DecompileOptions, decompile_policy, format_cacl
from .diagnostics import format_diagnostics
from .ir import CompiledPolicy
from .permissions import ObjectType


def _read_input(file_arg: str) -> tuple[str, str]:
    if file_arg == "-":
        return sys.stdin.read().removeprefix("\ufeff"), "<stdin>"
    p = Path(file_arg)
    return p.read_text(encoding="utf-8-sig"), str(p)


def _build_compile_config(args: argparse.Namespace) -> CompilerConfig:
    return CompilerConfig(
        target_object_type=ObjectType(args.target_type)
        if getattr(args, "target_type", None)
        else None,
    )


def _emit_diagnostics(diags, source: str, filename: str, as_json: bool) -> None:
    if not diags:
        return
    if as_json:
        print(
            json.dumps([d.to_dict() for d in diags], indent=2, ensure_ascii=False),
            file=sys.stderr,
        )
    else:
        print(
            format_diagnostics(diags, source=source, filename=filename), file=sys.stderr
        )


def cmd_check(args: argparse.Namespace) -> int:
    source, fname = _read_input(args.file)
    res = compile_cacl(source, config=_build_compile_config(args))
    _emit_diagnostics(res.diagnostics, source, fname, args.json)
    if res.ok and not args.json:
        assert res.policy is not None
        print(
            f"OK ({len(res.policy.rules)} rules, fingerprint={res.policy.fingerprint()[:12]})"
        )
    return 0 if res.ok else 1


def cmd_compile(args: argparse.Namespace) -> int:
    source, fname = _read_input(args.file)
    res = compile_cacl(source, config=_build_compile_config(args))
    _emit_diagnostics(res.diagnostics, source, fname, args.diag_json)
    if not res.ok or res.policy is None:
        return 1

    output = res.policy.to_dict()
    output["fingerprint"] = res.policy.fingerprint()

    text = json.dumps(output, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_decompile(args: argparse.Namespace) -> int:
    raw, _ = _read_input(args.file)
    policy = CompiledPolicy.from_dict(json.loads(raw))
    opts = DecompileOptions(
        fold_presets=args.fold_presets,
        prefer_to_syntax=not args.always_when,
    )
    text = decompile_policy(policy, opts=opts)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


def cmd_fmt(args: argparse.Namespace) -> int:
    source, fname = _read_input(args.file)
    cfg = _build_compile_config(args)
    opts = DecompileOptions(
        fold_presets=args.fold_presets,
        prefer_to_syntax=not args.always_when,
    )
    formatted, diags = format_cacl(source, compile_config=cfg, decompile_options=opts)
    _emit_diagnostics(diags, source, fname, False)
    if formatted is None:
        return 1
    if args.write and args.file != "-":
        Path(args.file).write_text(formatted, encoding="utf-8")
    else:
        print(formatted, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caclc", description="Standalone CACL (CEP 2) compiler & toolchain"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_compile_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--target-type",
            choices=["directory", "document"],
            help="Target object type hint",
        )

    p_check = sub.add_parser(
        "check", help="Validate syntax and semantics of a .cacl policy"
    )
    p_check.add_argument("file", help="Path to .cacl file (or '-')")
    p_check.add_argument("--json", action="store_true", help="Emit diagnostics as JSON")
    add_common_compile_flags(p_check)
    p_check.set_defaults(func=cmd_check)

    p_comp = sub.add_parser("compile", help="Compile .cacl into JSON IR")
    p_comp.add_argument("file", help="Path to .cacl file (or '-')")
    p_comp.add_argument("-o", "--output", help="Output JSON path")
    p_comp.add_argument(
        "--diag-json", action="store_true", help="Emit diagnostics as JSON"
    )
    add_common_compile_flags(p_comp)
    p_comp.set_defaults(func=cmd_compile)

    p_dec = sub.add_parser(
        "decompile", help="Decompile compiled JSON IR back to canonical .cacl"
    )
    p_dec.add_argument("file", help="Path to compiled IR JSON (or '-')")
    p_dec.add_argument("-o", "--output", help="Output .cacl path")
    p_dec.add_argument(
        "--fold-presets",
        action="store_true",
        help="Fold exact macro bitmasks when printing",
    )
    p_dec.add_argument(
        "--always-when", action="store_true", help="Emit `when` instead of `to` sugar"
    )
    p_dec.set_defaults(func=cmd_decompile)

    p_fmt = sub.add_parser("fmt", help="Format and canonicalize a .cacl file")
    p_fmt.add_argument("file", help="Path to .cacl file (or '-')")
    p_fmt.add_argument(
        "-w", "--write", action="store_true", help="Write formatted result in-place"
    )
    p_fmt.add_argument("--fold-presets", action="store_true")
    p_fmt.add_argument("--always-when", action="store_true")
    add_common_compile_flags(p_fmt)
    p_fmt.set_defaults(func=cmd_fmt)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
