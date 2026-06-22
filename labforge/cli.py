from __future__ import annotations

import argparse
from pathlib import Path

from .model import LabSpec
from .doctor import inspect_host, report_to_json, report_to_markdown
from .execution_plan import create_execution_plan, plan_to_json, plan_to_markdown
from .agent_orchestration import (
    render_agent_list,
    scaffold_agent_workspace,
    validate_agent_workspace,
)
from .io import write_text
from .providers.factory import list_providers
from .render import build_lab, render_docs
from .schema import export_schemas
from .service_artifacts import scaffold_service_artifacts, service_check
from .validate import validate_lab


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_lab(Path(args.lab))
    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Validation passed")
    return 0


def command_build(args: argparse.Namespace) -> int:
    root = Path(args.lab)
    errors = validate_lab(root)
    if errors and not args.force:
        print("Build blocked by validation errors:")
        for error in errors:
            print(f"- {error}")
        print("Use --force to render anyway.")
        return 1
    spec = LabSpec.load(root)
    build_lab(spec, Path(args.out), provider_name=args.provider, profile=args.profile)
    print(
        f"Built lab scaffold with provider {args.provider} "
        f"and profile {args.profile}: {Path(args.out).resolve()}"
    )
    return 0


def command_docs(args: argparse.Namespace) -> int:
    root = Path(args.lab)
    spec = LabSpec.load(root)
    render_docs(spec, Path(args.out), profile=args.profile)
    print(f"Rendered docs with profile {args.profile}: {Path(args.out).resolve()}")
    return 0


def command_schema_export(args: argparse.Namespace) -> int:
    paths = export_schemas(Path(args.out))
    print(f"Exported {len(paths)} schema files: {Path(args.out).resolve()}")
    for path in paths:
        print(f"- {path.name}")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    lab_root = Path(args.lab) if args.lab else None
    report = inspect_host(lab_root)
    if args.format == "json":
        print(report_to_json(report))
    else:
        print(report_to_markdown(report))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    lab_root = Path(args.lab)
    spec = LabSpec.load(lab_root)
    out = Path(args.out) if args.out else Path("output") / spec.lab_id
    plan = create_execution_plan(
        spec,
        lab_root,
        out,
        provider=args.provider,
        profile=args.profile,
    )
    if args.out:
        write_text(out / "docs" / "execution-plan.md", plan_to_markdown(plan))
        write_text(out / "docs" / "execution-plan.json", plan_to_json(plan))
        print(f"Rendered execution plan: {(out / 'docs' / 'execution-plan.md').resolve()}")
    elif args.format == "json":
        print(plan_to_json(plan))
    else:
        print(plan_to_markdown(plan))
    return 0


def command_agents_list(args: argparse.Namespace) -> int:
    print(render_agent_list())
    return 0


def command_agents_scaffold(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    out = Path(args.out) if args.out else Path("output") / spec.lab_id
    written = scaffold_agent_workspace(spec, out)
    print(f"Scaffolded agent workspace: {(out / '.ai').resolve()}")
    for path in written:
        print(f"- {path}")
    return 0


def command_agents_validate(args: argparse.Namespace) -> int:
    errors = validate_agent_workspace(Path(args.workspace))
    if errors:
        print("Agent workspace validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Agent workspace validation passed")
    return 0


def command_services_check(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    result = service_check(spec)
    if result.warnings:
        print("Service artifact warnings:")
        for warning in result.warnings:
            print(f"- {warning}")
    if result.errors:
        print("Service artifact check failed:")
        for error in result.errors:
            print(f"- {error}")
        return 1
    print("Service artifact check passed")
    return 0


def command_services_scaffold(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    written = scaffold_service_artifacts(spec, force=args.force)
    print(f"Scaffolded service artifact files under: {Path(args.lab).resolve()}")
    if written:
        for path in written:
            print(f"- {path}")
    else:
        print("No files written. Existing files were left unchanged. Use --force to overwrite.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="labforge")
    sub = parser.add_subparsers(dest="command", required=True)

    validate_parser = sub.add_parser("validate", help="Validate a lab spec")
    validate_parser.add_argument("lab")
    validate_parser.set_defaults(func=command_validate)

    build_parser = sub.add_parser("build", help="Build docker-compose and docs")
    build_parser.add_argument("lab")
    build_parser.add_argument("--out", required=True)
    build_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    build_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    build_parser.add_argument("--force", action="store_true")
    build_parser.set_defaults(func=command_build)

    docs_parser = sub.add_parser("docs", help="Render documentation only")
    docs_parser.add_argument("lab")
    docs_parser.add_argument("--out", required=True)
    docs_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    docs_parser.set_defaults(func=command_docs)

    schema_parser = sub.add_parser("schema", help="Schema utilities")
    schema_sub = schema_parser.add_subparsers(dest="schema_command", required=True)
    schema_export_parser = schema_sub.add_parser("export", help="Export JSON Schemas")
    schema_export_parser.add_argument("--out", required=True)
    schema_export_parser.set_defaults(func=command_schema_export)

    doctor_parser = sub.add_parser("doctor", help="Inspect host OS, WSL, Docker, and execution target")
    doctor_parser.add_argument("--lab", help="Optional lab root used to include deployment-model advice")
    doctor_parser.add_argument("--format", choices=["text", "json"], default="text")
    doctor_parser.set_defaults(func=command_doctor)

    plan_parser = sub.add_parser("plan", help="Create a host-aware lab execution plan")
    plan_parser.add_argument("lab")
    plan_parser.add_argument("--out")
    plan_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    plan_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    plan_parser.add_argument("--format", choices=["text", "json"], default="text")
    plan_parser.set_defaults(func=command_plan)

    agents_parser = sub.add_parser("agents", help="Agent orchestration utilities")
    agents_sub = agents_parser.add_subparsers(dest="agents_command", required=True)
    agents_list_parser = agents_sub.add_parser("list", help="List default specialist agent roles")
    agents_list_parser.set_defaults(func=command_agents_list)
    agents_scaffold_parser = agents_sub.add_parser("scaffold", help="Create a dry-run agent workspace")
    agents_scaffold_parser.add_argument("lab")
    agents_scaffold_parser.add_argument("--out")
    agents_scaffold_parser.set_defaults(func=command_agents_scaffold)
    agents_validate_parser = agents_sub.add_parser("validate", help="Validate a dry-run agent workspace")
    agents_validate_parser.add_argument("workspace")
    agents_validate_parser.set_defaults(func=command_agents_validate)

    services_parser = sub.add_parser("services", help="Service artifact utilities")
    services_sub = services_parser.add_subparsers(dest="services_command", required=True)
    services_check_parser = services_sub.add_parser("check", help="Validate service artifact directories")
    services_check_parser.add_argument("lab")
    services_check_parser.set_defaults(func=command_services_check)
    services_scaffold_parser = services_sub.add_parser("scaffold", help="Create service artifact directories and hook placeholders")
    services_scaffold_parser.add_argument("lab")
    services_scaffold_parser.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    services_scaffold_parser.set_defaults(func=command_services_scaffold)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
