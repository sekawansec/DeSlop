"""DeSlop command-line interface.

Currently exposes configuration introspection and synthetic dataset
generation. Later stages add ``doctor``, ``retest``, ``eval``, and ``demo``.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import ConfigError, ProgramRegistry, get_settings


def _cmd_config_list(args: argparse.Namespace) -> int:
    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    try:
        registry = ProgramRegistry.from_dir(config_dir)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if len(registry) == 0:
        print(f"No programs found in {config_dir}")
        return 0
    print(f"Programs in {config_dir}:")
    for program in registry:
        print(
            f"  - {program.id}: {program.name} "
            f"(in_scope={len(program.in_scope)}, "
            f"accounts={len(program.test_accounts)}, "
            f"staging={program.staging.base_url})"
        )
    return 0


def _cmd_config_show(args: argparse.Namespace) -> int:
    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    try:
        registry = ProgramRegistry.from_dir(config_dir)
        program = registry.get(args.program_id)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(program.model_dump_json(indent=2))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from .config import ProgramRegistry
    from .doctor import run_doctor

    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    try:
        registry = ProgramRegistry.from_dir(config_dir)
        program = registry.get(args.program_id)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = run_doctor(program, settings, probe_host=args.probe_host, skip_network=args.skip_network)
    print(report.render())
    return 0 if report.ok else 1


def _cmd_retest(args: argparse.Namespace) -> int:
    from .config import ProgramRegistry
    from .db.session import init_db, session_scope
    from .pipeline.retest import retest_report

    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    try:
        program = ProgramRegistry.from_dir(config_dir).get(args.program_id)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    init_db(settings)
    try:
        with session_scope() as session:
            result = retest_report(session, args.report_id, program, settings=settings)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    status = "STILL REPRODUCIBLE" if result.still_reproducible else "NO LONGER PROVEN"
    print(f"{result.report_id}: {status} (verdict={result.verdict}, run={result.run_id})")
    if result.evidence:
        print(f"evidence: {result.evidence}")
    return 0 if not result.still_reproducible else 1


def _cmd_init(args: argparse.Namespace) -> int:
    from .install import write_env

    result = write_env(
        args.env_file,
        force=args.force,
        dashboard_user=args.user,
        env=args.env,
        config_dir=args.config_dir or "./config/programs",
        llm_provider=args.llm_provider,
        llm_model=args.llm_model or "",
    )
    if not result.created:
        for note in result.notes:
            print(note)
        return 1
    print(f"Wrote {result.env_path}")
    print()
    print("  Dashboard login:")
    print(f"    username: {args.user}")
    print(f"    password: {result.dashboard_password}")
    print()
    for note in result.notes:
        print(f"  - {note}")
    print()
    print("Keep the password safe; it is not stored in plaintext anywhere else.")
    return 0


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"deslop {__version__}")
    return 0


def _cmd_dataset_generate(args: argparse.Namespace) -> int:
    from .dataset import generate_dataset
    from .dataset.io import write_jsonl

    reports = generate_dataset(seed=args.seed, per_category=args.per)
    out = write_jsonl(reports, args.out, seed=args.seed)
    by_label: dict[str, int] = {}
    for r in reports:
        by_label[r.label.value] = by_label.get(r.label.value, 0) + 1
    print(f"Wrote {len(reports)} synthetic reports to {out}")
    for label in sorted(by_label):
        print(f"  {label}: {by_label[label]}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    if args.init_db:
        from .db.session import init_db

        init_db(settings)
    uvicorn.run(
        "deslop.web.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level=settings.log_level.lower(),
    )
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    from .config import ProgramRegistry
    from .dataset import generate_dataset
    from .dataset.io import read_jsonl
    from .eval import evaluate, to_markdown

    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    try:
        program = ProgramRegistry.from_dir(config_dir).get(args.program_id)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dataset and args.dataset != "-":
        reports = read_jsonl(args.dataset)
    else:
        reports = generate_dataset(seed=args.seed, per_category=args.per)

    if args.program_id == "lab":
        try:
            from lab.recipes.lab_recipes import register_lab_recipes

            register_lab_recipes()
        except ImportError:
            pass

    result = evaluate(reports, program, settings)
    print(to_markdown([result]))
    print()
    print(f"provider: {result.provider}")
    print(f"false_reproduced: {result.metrics.false_reproduced} (target: 0)")
    for label in sorted(result.per_label):
        row = result.per_label[label]
        print(f"  {label}: {row['total']}")
    if result.metrics.injection_block_rate < 1.0:
        print("WARNING: some injection attempts were not blocked")
    if result.metrics.false_reproduced > 0:
        return 1
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    settings = get_settings()
    config_dir = args.config_dir or settings.config_dir
    return run_demo(
        config_dir, settings, seed=args.seed, per=args.per, program_id=args.program
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deslop", description="DeSlop CLI")
    parser.add_argument("--config-dir", default=None, help="directory of program YAML files")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="generate a .env with secrets (one-command setup)")
    init.add_argument("--env-file", default=".env")
    init.add_argument("--force", action="store_true", help="overwrite an existing .env")
    init.add_argument("--user", default="admin", help="dashboard username")
    init.add_argument("--env", default="dev", help="environment name (dev/prod)")
    init.add_argument("--llm-provider", default="none", help="anthropic|openai|ollama|none")
    init.add_argument("--llm-model", default=None)
    init.add_argument("--config-dir", default=None)

    config = sub.add_parser("config", help="inspect program configuration")
    config_sub = config.add_subparsers(dest="config_command")
    config_sub.add_parser("list", help="list loaded programs")
    show = config_sub.add_parser("show", help="show one program's full config")
    show.add_argument("program_id")

    dataset = sub.add_parser("dataset", help="synthetic evaluation dataset")
    dataset_sub = dataset.add_subparsers(dest="dataset_command")
    gen = dataset_sub.add_parser("generate", help="generate the synthetic dataset")
    gen.add_argument("--out", default="data/synthetic-dataset.jsonl")
    gen.add_argument("--seed", type=int, default=1337)
    gen.add_argument(
        "--per", type=int, default=None, help="valid reports per bug class (default 3)"
    )

    eval_p = sub.add_parser("eval", help="run the evaluation harness")
    eval_p.add_argument("program_id")
    eval_p.add_argument("--dataset", default=None, help="JSONL dataset (default: generate in-memory)")
    eval_p.add_argument("--seed", type=int, default=1337)
    eval_p.add_argument("--per", type=int, default=None)

    serve = sub.add_parser("serve", help="run the web app (form, status page, dashboard)")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--init-db", action="store_true", help="create tables on startup")

    demo = sub.add_parser("demo", help="run the demo scenario")
    demo.add_argument("--seed", type=int, default=1337)
    demo.add_argument("--per", type=int, default=None)
    demo.add_argument("--program", default="lab", help="program id to demo (lab or dvwa)")

    retest = sub.add_parser("retest", help="re-run reproduction after a fix")
    retest.add_argument("program_id")
    retest.add_argument("report_id")

    doctor = sub.add_parser("doctor", help="verify environment readiness for reproduction")
    doctor.add_argument("program_id")
    doctor.add_argument("--probe-host", default="example.com")
    doctor.add_argument("--skip-network", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        return _cmd_version(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "config":
        if args.config_command == "list":
            return _cmd_config_list(args)
        if args.config_command == "show":
            return _cmd_config_show(args)
        parser.parse_args(["config", "--help"])
        return 0
    if args.command == "dataset":
        if args.dataset_command == "generate":
            return _cmd_dataset_generate(args)
        parser.parse_args(["dataset", "--help"])
        return 0
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "eval":
        return _cmd_eval(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "retest":
        return _cmd_retest(args)
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
