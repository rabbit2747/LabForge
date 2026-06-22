from __future__ import annotations

import argparse
from pathlib import Path

from .model import LabSpec
from .providers.factory import list_providers
from .render import build_lab, render_docs
from .schema import export_schemas
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

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
