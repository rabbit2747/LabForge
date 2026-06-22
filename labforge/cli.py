from __future__ import annotations

import argparse
from pathlib import Path

from .model import LabSpec
from .render import build_lab, render_docs
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
    build_lab(spec, Path(args.out))
    print(f"Built lab scaffold: {Path(args.out).resolve()}")
    return 0


def command_docs(args: argparse.Namespace) -> int:
    root = Path(args.lab)
    spec = LabSpec.load(root)
    render_docs(spec, Path(args.out))
    print(f"Rendered docs: {Path(args.out).resolve()}")
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
    build_parser.add_argument("--force", action="store_true")
    build_parser.set_defaults(func=command_build)

    docs_parser = sub.add_parser("docs", help="Render documentation only")
    docs_parser.add_argument("lab")
    docs_parser.add_argument("--out", required=True)
    docs_parser.set_defaults(func=command_docs)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

