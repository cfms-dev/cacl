import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from .analyzer import CompilerConfig, compile_cacl
from .decompiler import DecompileOptions, UserRenderMode, decompile_policy, format_cacl
from .diagnostics import format_diagnostics
from .evaluator import NamespaceNode, Subject, evaluate_access
from .identity import InMemoryPrincipalResolver
from .ir import CompiledPolicy
from .permissions import ATOMIC_OP_BY_NAME, ObjectState, ObjectType


def _load_resolver(path: str | None) -> InMemoryPrincipalResolver | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return InMemoryPrincipalResolver.from_dict(data)


def _read_input(file_arg: str) -> tuple[str, str]:
    if file_arg == "-":
        return sys.stdin.read().removeprefix("\ufeff"), "<stdin>"
    p = Path(file_arg)
    return p.read_text(encoding="utf-8-sig"), str(p)


def _build_compile_config(args: argparse.Namespace) -> CompilerConfig:
    return CompilerConfig(
        resolver=_load_resolver(getattr(args, "users", None)),
        strict_principal_existence=not getattr(args, "no_strict_principals", False),
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

    if args.ssot_node:
        output = res.policy.to_ssot_rows(node_id=args.ssot_node)
    else:
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
        resolver=_load_resolver(args.users),
        user_mode=UserRenderMode(args.user_mode),
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
        resolver=cfg.resolver,
        user_mode=UserRenderMode(args.user_mode),
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


def cmd_eval(args: argparse.Namespace) -> int:
    """Evaluate a scenario JSON containing a node path chain + subject + operation."""
    scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
    resolver = _load_resolver(args.users)
    cfg = CompilerConfig(resolver=resolver, strict_principal_existence=False)

    chain: list[NamespaceNode] = []
    for node_def in scenario["path"]:
        res = compile_cacl(node_def["cacl"], config=cfg)
        if not res.ok or res.policy is None:
            print(
                format_diagnostics(res.diagnostics, node_def["cacl"], node_def["name"]),
                file=sys.stderr,
            )
            return 1
        chain.append(
            NamespaceNode(
                node_id=node_def["id"],
                name=node_def["name"],
                object_type=ObjectType(node_def["type"]),
                state=ObjectState(node_def.get("state", "normal")),
                policy=res.policy,
            )
        )

    subj_def = scenario["subject"]
    subject = Subject(
        user_id=UUID(subj_def["user_id"]),
        username=subj_def.get("username"),
        groups=frozenset(subj_def.get("groups", [])),
        perms=frozenset(subj_def.get("perms", [])),
    )
    op = ATOMIC_OP_BY_NAME[args.op].op
    eval_time = (
        datetime.fromisoformat(args.at).astimezone(UTC)
        if args.at
        else datetime.now(UTC)
    )
    decision = evaluate_access(subject, chain, op, eval_time_utc=eval_time)
    print(
        json.dumps(
            {
                "allowed": decision.allowed,
                "step": decision.step,
                "reason": decision.reason,
                "matched_denies": [
                    {
                        "node": d.node_name,
                        "distance": d.distance,
                        "rule_index": d.rule_index,
                        "remark": d.remark,
                    }
                    for d in decision.matched_denies
                ],
                "matched_allows": [
                    {
                        "node": a.node_name,
                        "distance": a.distance,
                        "rule_index": a.rule_index,
                        "remark": a.remark,
                    }
                    for a in decision.matched_allows
                ],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if decision.allowed else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caclc", description="Standalone CACL (CEP 2) compiler & toolchain"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_compile_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--users",
            help="Path to JSON principal directory for optional existence checks / # comment annotations",
        )
        p.add_argument(
            "--no-strict-principals",
            action="store_true",
            help="Warn instead of error on unknown principals",
        )
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

    p_comp = sub.add_parser(
        "compile", help="Compile .cacl into JSON IR or relational SSOT rows"
    )
    p_comp.add_argument("file", help="Path to .cacl file (or '-')")
    p_comp.add_argument("-o", "--output", help="Output JSON path")
    p_comp.add_argument(
        "--ssot-node", help="Export relational SSOT table rows for this node_id"
    )
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
        "--users",
        help="Principal directory JSON for UUID -> # @username comment annotations",
    )
    p_dec.add_argument(
        "--user-mode", choices=["uuid", "uuid_annotated"], default="uuid"
    )
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
    p_fmt.add_argument(
        "--user-mode",
        choices=["uuid", "uuid_annotated"],
        default="uuid",
    )
    p_fmt.add_argument("--fold-presets", action="store_true")
    p_fmt.add_argument("--always-when", action="store_true")
    add_common_compile_flags(p_fmt)
    p_fmt.set_defaults(func=cmd_fmt)

    p_eval = sub.add_parser(
        "eval", help="Simulate CEP 2 Section 6 runtime evaluation with trace"
    )
    p_eval.add_argument("scenario", help="Path to scenario JSON file")
    p_eval.add_argument("--op", required=True, choices=sorted(ATOMIC_OP_BY_NAME.keys()))
    p_eval.add_argument("--at", help="Evaluation UTC timestamp (RFC 3339)")
    p_eval.add_argument("--users", help="Principal directory JSON")
    p_eval.set_defaults(func=cmd_eval)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
