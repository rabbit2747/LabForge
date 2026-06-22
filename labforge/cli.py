from __future__ import annotations

import argparse
from pathlib import Path

from .model import LabSpec
from .agent_adapters import AgentAdapterError, get_agent_adapter, render_agent_adapter_list
from .control_selection import apply_control_selection, render_control_catalog
from .doctor import inspect_host, report_to_json, report_to_markdown
from .execution_plan import create_execution_plan, plan_to_json, plan_to_markdown
from .implementation_plan import (
    create_service_agent_packages,
    create_service_implementation_plan,
    implementation_plan_to_json,
    implementation_plan_to_markdown,
)
from .intake import create_intake_template, scaffold_lab_from_intake
from .packaging import create_supervisor_package
from .agent_orchestration import (
    append_agent_decision,
    create_agent_execution_packages,
    create_agent_run_plan,
    create_agent_review,
    render_agent_list,
    review_to_json,
    review_to_markdown,
    run_plan_to_json,
    run_plan_to_markdown,
    scaffold_agent_workspace,
    validate_agent_workspace,
    write_agent_review,
    write_agent_result_stub,
)
from .io import write_text
from .linting import lint_lab, lint_report_to_json, lint_report_to_markdown
from .providers.factory import list_providers
from .provider_lifecycle import provider_lifecycle, render_lifecycle_result
from .qa import run_qa_smoke, run_release_gate
from .render import build_lab, render_docs
from .schema import export_schemas
from .service_verification import service_verification_to_json, service_verification_to_markdown, verify_services
from .service_templates import list_service_templates
from .vulnerability_plugins import list_vulnerability_plugins
from .workflow import create_workflow_report, workflow_report_to_json, workflow_report_to_markdown
from .service_artifacts import (
    apply_service_result,
    apply_service_results,
    materialize_service_runtimes,
    review_service_result,
    review_service_results,
    run_service_hooks,
    scaffold_service_artifacts,
    service_check,
    service_result_batch_apply_to_markdown,
    service_result_batch_review_to_markdown,
    service_result_apply_to_markdown,
    service_result_review_to_markdown,
)
from .starter import init_lab
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


def command_lint(args: argparse.Namespace) -> int:
    report = lint_lab(Path(args.lab))
    if args.out:
        out = Path(args.out)
        write_text(out, lint_report_to_json(report) if args.format == "json" else lint_report_to_markdown(report))
        print(f"Rendered lint report: {out.resolve()}")
    elif args.format == "json":
        print(lint_report_to_json(report))
    else:
        print(lint_report_to_markdown(report))
    if report.status == "failed":
        return 1
    if args.strict and report.status == "warning":
        return 1
    return 0


def command_init(args: argparse.Namespace) -> int:
    written = init_lab(Path(args.out), lab_id=args.lab_id, title=args.title, force=args.force)
    print(f"Initialized LabForge scenario template: {Path(args.out).resolve()}")
    if written:
        for path in written:
            print(f"- {path}")
    else:
        print("No files written. Existing files were left unchanged. Use --force to overwrite.")
    return 0


def command_intake_template(args: argparse.Namespace) -> int:
    written = create_intake_template(
        Path(args.out),
        lab_id=args.lab_id,
        title=args.title,
        force=args.force,
    )
    print(f"Rendered scenario intake template: {Path(args.out).resolve()}")
    if written:
        for path in written:
            print(f"- {path}")
    else:
        print("No files written. Existing files were left unchanged. Use --force to overwrite.")
    return 0


def command_intake_scaffold(args: argparse.Namespace) -> int:
    written = scaffold_lab_from_intake(Path(args.from_file), Path(args.out), force=args.force)
    print(f"Scaffolded LabForge lab from intake: {Path(args.out).resolve()}")
    if written:
        for path in written:
            print(f"- {path}")
    else:
        print("No files written. Existing files were left unchanged. Use --force to overwrite.")
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


def command_package(args: argparse.Namespace) -> int:
    report = create_supervisor_package(
        Path(args.lab),
        Path(args.out),
        provider=args.provider,
        profile=args.profile,
        materialize=args.materialize,
        force=args.force,
        all_profiles=args.all_profiles,
    )
    print(f"Package status: {report.status}")
    print(f"- {(Path(args.out) / 'package-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'generated').resolve()}")
    print(f"- {(Path(args.out) / 'reports').resolve()}")
    print(f"- {(Path(args.out) / 'qa').resolve()}")
    return 0 if report.status in {"passed", "warning"} else 1


def command_workflow_status(args: argparse.Namespace) -> int:
    report = create_workflow_report(
        Path(args.lab),
        provider=args.provider,
        profile=args.profile,
        result_dir=Path(args.results) if args.results else None,
        package_dir=Path(args.package_dir) if args.package_dir else None,
    )
    if args.out:
        out = Path(args.out)
        write_text(out, workflow_report_to_json(report) if args.format == "json" else workflow_report_to_markdown(report))
        print(f"Rendered workflow status: {out.resolve()}")
    elif args.format == "json":
        print(workflow_report_to_json(report))
    else:
        print(workflow_report_to_markdown(report))
    return 0 if report.status != "blocked" else 1


def command_workflow_plan(args: argparse.Namespace) -> int:
    return command_workflow_status(args)


def command_controls_list(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    print(render_control_catalog(spec))
    return 0


def command_controls_apply(args: argparse.Namespace) -> int:
    try:
        data = apply_control_selection(
            Path(args.lab),
            args.select,
            clear=args.clear,
            profile=args.profile,
            detection_feedback=args.detection_feedback,
            allow_student_log_access=args.allow_student_log_access,
        )
    except ValueError as exc:
        print(f"Control selection failed: {exc}")
        return 1
    print(f"Updated supervisor selection: {(Path(args.lab) / 'supervisor-selection.yaml').resolve()}")
    for category, values in (data.get("selected_controls", {}) or {}).items():
        joined = ", ".join(str(value) for value in values) if values else "(none)"
        print(f"- {category}: {joined}")
    return 0


def command_agents_list(args: argparse.Namespace) -> int:
    print(render_agent_list())
    return 0


def command_agents_adapters(args: argparse.Namespace) -> int:
    print(render_agent_adapter_list())
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


def command_agents_plan_run(args: argparse.Namespace) -> int:
    try:
        get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    context_root = Path(args.context_root) if args.context_root else None
    plan = create_agent_run_plan(Path(args.workspace), adapter=args.adapter, context_root=context_root)
    if args.out:
        out = Path(args.out)
        write_text(out, run_plan_to_json(plan) if args.format == "json" else run_plan_to_markdown(plan))
        print(f"Rendered agent run plan: {out.resolve()}")
    elif args.format == "json":
        print(run_plan_to_json(plan))
    else:
        print(run_plan_to_markdown(plan))
    return 0


def command_agents_run(args: argparse.Namespace) -> int:
    try:
        adapter = get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    if adapter.status != "available":
        print(f"Agent adapter `{args.adapter}` is registered but not implemented yet.")
        return 1
    if args.execute and not adapter.live_execution:
        print(f"Agent adapter `{args.adapter}` does not support live execution.")
        return 1
    errors = validate_agent_workspace(Path(args.workspace))
    if errors:
        print("Agent workspace validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    try:
        written = create_agent_execution_packages(
            Path(args.workspace),
            adapter=args.adapter,
            agent_id=args.agent,
            context_root=Path(args.context_root) if args.context_root else None,
        )
    except ValueError as exc:
        print(str(exc))
        return 1
    prepared = []
    executed = []
    for path in written:
        if path.name == "run-plan.yaml":
            continue
        if args.execute:
            executed.append(adapter.execute(path))
        else:
            prepared.append(adapter.prepare(path))
    mode = "live" if args.execute else "dry-run"
    print(f"Created {mode} agent execution packages under: {(Path(args.workspace) / '.ai' / 'run').resolve() if Path(args.workspace).name != '.ai' else (Path(args.workspace) / 'run').resolve()}")
    for path in written:
        print(f"- {path}")
    for result in prepared:
        if result.invocation_file:
            print(f"- {result.invocation_file}")
    failed = [result for result in executed if result.status != "complete"]
    for result in executed:
        print(f"- {result.task_id}: {result.status} ({result.message})")
        if result.output_file:
            print(f"  output: {result.output_file}")
        if result.transcript_file:
            print(f"  transcript: {result.transcript_file}")
    return 1 if failed else 0


def command_agents_review(args: argparse.Namespace) -> int:
    review = create_agent_review(Path(args.workspace))
    if args.write:
        written = write_agent_review(Path(args.workspace))
        print("Wrote agent review files:")
        for path in written:
            print(f"- {path}")
        return 0 if review.ready_for_supervisor else 1
    if args.format == "json":
        print(review_to_json(review))
    else:
        print(review_to_markdown(review))
    return 0 if review.ready_for_supervisor else 1


def command_agents_decide(args: argparse.Namespace) -> int:
    try:
        path = append_agent_decision(
            Path(args.workspace),
            decision=args.decision,
            task_id=args.task_id,
            reason=args.reason,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(str(exc))
        return 1
    print(f"Updated decision log: {path.resolve()}")
    return 0


def command_agents_result_stub(args: argparse.Namespace) -> int:
    try:
        path = write_agent_result_stub(
            Path(args.workspace),
            task_id=args.task_id,
            status=args.status,
            summary=args.summary,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(str(exc))
        return 1
    print(f"Updated agent result: {path.resolve()}")
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


def command_services_verify(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = verify_services(spec)
    if args.out:
        out = Path(args.out)
        write_text(out, service_verification_to_json(report) if args.format == "json" else service_verification_to_markdown(report))
        print(f"Rendered service verification report: {out.resolve()}")
    elif args.format == "json":
        print(service_verification_to_json(report))
    else:
        print(service_verification_to_markdown(report))
    if report.status == "failed":
        return 1
    if args.strict and report.status == "warning":
        return 1
    return 0


def command_services_plan(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    plan = create_service_implementation_plan(spec, Path(args.out) if args.out else None)
    if args.out:
        print(f"Rendered service implementation plan: {Path(args.out).resolve()}")
    elif args.format == "json":
        print(implementation_plan_to_json(plan))
    else:
        print(implementation_plan_to_markdown(plan))
    return 0


def command_services_agent_packages(args: argparse.Namespace) -> int:
    try:
        get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    spec = LabSpec.load(Path(args.lab))
    written = create_service_agent_packages(spec, Path(args.out), adapter=args.adapter)
    print(f"Created service builder packages under: {(Path(args.out) / '.ai' / 'service-build').resolve()}")
    for path in written:
        print(f"- {path}")
    return 0


def command_services_templates(args: argparse.Namespace) -> int:
    lines = [
        "# Service Templates",
        "",
        "| Template | Description | Aliases |",
        "|---|---|---|",
    ]
    for template in list_service_templates():
        aliases = ", ".join(f"`{alias}`" for alias in template.aliases) or "-"
        lines.append(f"| `{template.template_id}` | {template.description} | {aliases} |")
    lines.append("")
    print("\n".join(lines))
    return 0


def command_services_vulnerability_plugins(args: argparse.Namespace) -> int:
    lines = [
        "# Vulnerability Plugins",
        "",
        "These are scenario-specific behavior contracts, not complete puzzle generators.",
        "",
        "| Plugin | Compatible Templates | MITRE | Description |",
        "|---|---|---|---|",
    ]
    for plugin in list_vulnerability_plugins():
        templates = ", ".join(f"`{item}`" for item in plugin.compatible_templates)
        mitre = ", ".join(f"`{item}`" for item in plugin.mitre_techniques)
        lines.append(f"| `{plugin.plugin_id}` | {templates} | {mitre} | {plugin.description} |")
    lines.append("")
    print("\n".join(lines))
    return 0


def command_services_apply_result(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = apply_service_result(
        spec,
        Path(args.result),
        force=args.force,
        dry_run=args.dry_run,
    )
    if args.out:
        out = Path(args.out)
        write_text(out, report.model_dump_json(indent=2) if args.format == "json" else service_result_apply_to_markdown(report))
        print(f"Rendered service apply report: {out.resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_result_apply_to_markdown(report))
    return 0 if report.status == "passed" else 1


def command_services_apply_results(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = apply_service_results(
        spec,
        Path(args.results),
        force=args.force,
        dry_run=not args.execute,
    )
    if args.out:
        out = Path(args.out)
        write_text(out, report.model_dump_json(indent=2) if args.format == "json" else service_result_batch_apply_to_markdown(report))
        print(f"Rendered service batch apply report: {out.resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_result_batch_apply_to_markdown(report))
    return 0 if report.status == "passed" else 1


def command_services_review_result(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = review_service_result(spec, Path(args.result), force=args.force)
    if args.out:
        out = Path(args.out)
        write_text(out, report.model_dump_json(indent=2) if args.format == "json" else service_result_review_to_markdown(report))
        print(f"Rendered service result review: {out.resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_result_review_to_markdown(report))
    return 0 if report.status == "ready" else 1


def command_services_review_results(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = review_service_results(spec, Path(args.results), force=args.force)
    if args.out:
        out = Path(args.out)
        write_text(out, report.model_dump_json(indent=2) if args.format == "json" else service_result_batch_review_to_markdown(report))
        print(f"Rendered service result batch review: {out.resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_result_batch_review_to_markdown(report))
    return 0 if report.status == "ready" else 1


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


def command_services_materialize(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    written = materialize_service_runtimes(spec, force=args.force)
    print(f"Materialized service runtimes under: {Path(args.lab).resolve()}")
    if written:
        for path in written:
            print(f"- {path}")
    else:
        print("No files written. Existing files were left unchanged. Use --force to overwrite.")
    return 0


def command_services_hook(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    runs, errors = run_service_hooks(
        spec,
        args.hook,
        service=args.service,
        dry_run=args.dry_run,
    )
    failed = False
    for error in errors:
        print(f"- {error}")
        failed = True
    for run in runs:
        status = "passed" if run.returncode == 0 else "failed"
        print(f"[{status}] {run.service} {run.hook}: {run.path}")
        if run.stdout:
            print(run.stdout)
        if run.stderr:
            print(run.stderr)
        if run.returncode != 0:
            failed = True
    return 1 if failed else 0


def command_qa_smoke(args: argparse.Namespace) -> int:
    report = run_qa_smoke(
        Path(args.lab),
        Path(args.out),
        provider=args.provider,
        profile=args.profile,
        materialize=args.materialize,
        force=args.force,
    )
    print(f"QA smoke status: {report.status}")
    print(f"- {(Path(args.out) / 'qa-smoke-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'qa-smoke-report.yaml').resolve()}")
    return 0 if report.status in {"passed", "warning"} else 1


def command_qa_release_gate(args: argparse.Namespace) -> int:
    report = run_release_gate(
        Path(args.lab),
        Path(args.out),
        provider=args.provider,
        profile=args.profile,
        materialize=args.materialize,
        force=args.force,
    )
    print(f"Release gate status: {report.status}")
    print(f"- {(Path(args.out) / 'release-gate-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'release-gate-report.yaml').resolve()}")
    return 0 if report.status == "passed" else 1


def command_provider_lifecycle(args: argparse.Namespace) -> int:
    result = provider_lifecycle(
        Path(args.output),
        provider=args.provider,
        action=args.lifecycle_action,
        execute=args.execute,
        remove_volumes=args.volumes,
    )
    print(render_lifecycle_result(result))
    if result.status in {"planned", "completed", "not-implemented"}:
        return 0 if result.status != "not-implemented" else 1
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="labforge")
    sub = parser.add_subparsers(dest="command", required=True)

    validate_parser = sub.add_parser("validate", help="Validate a lab spec")
    validate_parser.add_argument("lab")
    validate_parser.set_defaults(func=command_validate)

    lint_parser = sub.add_parser("lint", help="Run quality checks for placeholders and weak scenario structure")
    lint_parser.add_argument("lab")
    lint_parser.add_argument("--format", choices=["text", "json"], default="text")
    lint_parser.add_argument("--out")
    lint_parser.add_argument("--strict", action="store_true", help="Return a non-zero exit code when warnings are present")
    lint_parser.set_defaults(func=command_lint)

    init_parser = sub.add_parser("init", help="Create a new LabForge scenario template")
    init_parser.add_argument("--out", required=True)
    init_parser.add_argument("--lab-id", required=True)
    init_parser.add_argument("--title", required=True)
    init_parser.add_argument("--force", action="store_true")
    init_parser.set_defaults(func=command_init)

    intake_parser = sub.add_parser("intake", help="Scenario intake utilities")
    intake_sub = intake_parser.add_subparsers(dest="intake_command", required=True)
    intake_template_parser = intake_sub.add_parser("template", help="Create a human scenario intake template")
    intake_template_parser.add_argument("--out", required=True)
    intake_template_parser.add_argument("--lab-id", required=True)
    intake_template_parser.add_argument("--title", required=True)
    intake_template_parser.add_argument("--force", action="store_true")
    intake_template_parser.set_defaults(func=command_intake_template)
    intake_scaffold_parser = intake_sub.add_parser("scaffold", help="Create a LabForge draft from scenario-intake.yaml")
    intake_scaffold_parser.add_argument("--from", dest="from_file", required=True)
    intake_scaffold_parser.add_argument("--out", required=True)
    intake_scaffold_parser.add_argument("--force", action="store_true")
    intake_scaffold_parser.set_defaults(func=command_intake_scaffold)

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

    package_parser = sub.add_parser("package", help="Create a supervisor-ready design, provider, and QA package")
    package_parser.add_argument("lab")
    package_parser.add_argument("--out", required=True)
    package_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    package_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    package_parser.add_argument("--materialize", action="store_true")
    package_parser.add_argument("--all-profiles", action="store_true", help="Also render unprotected and protected provider outputs side by side")
    package_parser.add_argument("--force", action="store_true")
    package_parser.set_defaults(func=command_package)

    workflow_parser = sub.add_parser("workflow", help="Inspect lab build workflow status and next commands")
    workflow_sub = workflow_parser.add_subparsers(dest="workflow_command", required=True)
    for workflow_command, help_text, func in (
        ("status", "Report current workflow status", command_workflow_status),
        ("plan", "Render the next-command workflow plan", command_workflow_plan),
    ):
        workflow_command_parser = workflow_sub.add_parser(workflow_command, help=help_text)
        workflow_command_parser.add_argument("lab")
        workflow_command_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
        workflow_command_parser.add_argument("--profile", default="protected", choices=["unprotected", "protected"])
        workflow_command_parser.add_argument("--results", help="Directory containing service-builder *.result.yaml files")
        workflow_command_parser.add_argument("--package-dir", help="Expected supervisor package output directory")
        workflow_command_parser.add_argument("--format", choices=["text", "json"], default="text")
        workflow_command_parser.add_argument("--out")
        workflow_command_parser.set_defaults(func=func)

    controls_parser = sub.add_parser("controls", help="Security control catalog and supervisor selection utilities")
    controls_sub = controls_parser.add_subparsers(dest="controls_command", required=True)
    controls_list_parser = controls_sub.add_parser("list", help="List available and selected security controls")
    controls_list_parser.add_argument("lab")
    controls_list_parser.set_defaults(func=command_controls_list)
    controls_apply_parser = controls_sub.add_parser("apply", help="Apply supervisor security control selections")
    controls_apply_parser.add_argument("lab")
    controls_apply_parser.add_argument("--select", action="append", default=[], help="Selection in CATEGORY=CONTROL_ID format. Can be repeated.")
    controls_apply_parser.add_argument("--clear", action="store_true", help="Clear existing selected controls before applying selections")
    controls_apply_parser.add_argument("--profile", choices=["unprotected", "protected"])
    controls_apply_parser.add_argument("--detection-feedback", choices=["none", "instructor_only", "learner_visible"])
    controls_apply_parser.add_argument("--allow-student-log-access", action="store_true")
    controls_apply_parser.set_defaults(func=command_controls_apply)

    agents_parser = sub.add_parser("agents", help="Agent orchestration utilities")
    agents_sub = agents_parser.add_subparsers(dest="agents_command", required=True)
    agents_list_parser = agents_sub.add_parser("list", help="List default specialist agent roles")
    agents_list_parser.set_defaults(func=command_agents_list)
    agents_adapters_parser = agents_sub.add_parser("adapters", help="List registered agent adapters")
    agents_adapters_parser.set_defaults(func=command_agents_adapters)
    agents_scaffold_parser = agents_sub.add_parser("scaffold", help="Create a dry-run agent workspace")
    agents_scaffold_parser.add_argument("lab")
    agents_scaffold_parser.add_argument("--out")
    agents_scaffold_parser.set_defaults(func=command_agents_scaffold)
    agents_validate_parser = agents_sub.add_parser("validate", help="Validate a dry-run agent workspace")
    agents_validate_parser.add_argument("workspace")
    agents_validate_parser.set_defaults(func=command_agents_validate)
    agents_plan_run_parser = agents_sub.add_parser("plan-run", help="Create an agent execution readiness plan")
    agents_plan_run_parser.add_argument("workspace")
    agents_plan_run_parser.add_argument("--adapter", default="manual")
    agents_plan_run_parser.add_argument("--context-root", help="Scenario directory used to resolve task context files")
    agents_plan_run_parser.add_argument("--format", choices=["text", "json"], default="text")
    agents_plan_run_parser.add_argument("--out")
    agents_plan_run_parser.set_defaults(func=command_agents_plan_run)
    agents_run_parser = agents_sub.add_parser("run", help="Create or execute agent execution packages")
    agents_run_parser.add_argument("workspace")
    agents_run_mode = agents_run_parser.add_mutually_exclusive_group()
    agents_run_mode.add_argument("--dry-run", action="store_true", help="Create execution packages without calling an LLM. This is the default.")
    agents_run_mode.add_argument("--execute", action="store_true", help="Call the selected live adapter and write agent result files.")
    agents_run_parser.add_argument("--adapter", default="manual")
    agents_run_parser.add_argument("--agent", help="Only package one agent_id")
    agents_run_parser.add_argument("--context-root", help="Scenario directory used to resolve task context files")
    agents_run_parser.set_defaults(func=command_agents_run)
    agents_review_parser = agents_sub.add_parser("review", help="Review agent result outputs")
    agents_review_parser.add_argument("workspace")
    agents_review_parser.add_argument("--format", choices=["text", "json"], default="text")
    agents_review_parser.add_argument("--write", action="store_true", help="Write review files under .ai/reviews")
    agents_review_parser.set_defaults(func=command_agents_review)
    agents_decide_parser = agents_sub.add_parser("decide", help="Append a supervisor decision log item")
    agents_decide_parser.add_argument("workspace")
    agents_decide_parser.add_argument("--decision", choices=["accepted", "rejected", "open-questions"], required=True)
    agents_decide_parser.add_argument("--task-id", required=True)
    agents_decide_parser.add_argument("--reason", required=True)
    agents_decide_parser.set_defaults(func=command_agents_decide)
    agents_result_stub_parser = agents_sub.add_parser("result-stub", help="Update an agent result YAML with a schema-valid status and summary")
    agents_result_stub_parser.add_argument("workspace")
    agents_result_stub_parser.add_argument("--task-id", required=True)
    agents_result_stub_parser.add_argument("--status", choices=["not-started", "draft", "complete", "blocked", "needs-review"], required=True)
    agents_result_stub_parser.add_argument("--summary", required=True)
    agents_result_stub_parser.set_defaults(func=command_agents_result_stub)

    services_parser = sub.add_parser("services", help="Service artifact utilities")
    services_sub = services_parser.add_subparsers(dest="services_command", required=True)
    services_templates_parser = services_sub.add_parser("templates", help="List built-in service infrastructure templates")
    services_templates_parser.set_defaults(func=command_services_templates)
    services_vuln_plugins_parser = services_sub.add_parser("vulnerability-plugins", help="List built-in scenario-specific vulnerability plugin contracts")
    services_vuln_plugins_parser.set_defaults(func=command_services_vulnerability_plugins)
    services_check_parser = services_sub.add_parser("check", help="Validate service artifact directories")
    services_check_parser.add_argument("lab")
    services_check_parser.set_defaults(func=command_services_check)
    services_verify_parser = services_sub.add_parser("verify", help="Verify service implementation quality gates")
    services_verify_parser.add_argument("lab")
    services_verify_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_verify_parser.add_argument("--out")
    services_verify_parser.add_argument("--strict", action="store_true", help="Return non-zero when warnings are present")
    services_verify_parser.set_defaults(func=command_services_verify)
    services_plan_parser = services_sub.add_parser("plan", help="Create per-service implementation task plan")
    services_plan_parser.add_argument("lab")
    services_plan_parser.add_argument("--out")
    services_plan_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_plan_parser.set_defaults(func=command_services_plan)
    services_agent_packages_parser = services_sub.add_parser("agent-packages", help="Create per-service service-builder agent packages")
    services_agent_packages_parser.add_argument("lab")
    services_agent_packages_parser.add_argument("--out", required=True)
    services_agent_packages_parser.add_argument("--adapter", default="manual")
    services_agent_packages_parser.set_defaults(func=command_services_agent_packages)
    services_review_result_parser = services_sub.add_parser("review-result", help="Review a service-builder result before applying it")
    services_review_result_parser.add_argument("lab")
    services_review_result_parser.add_argument("--result", required=True, help="Path to a service result YAML file")
    services_review_result_parser.add_argument("--force", action="store_true", help="Treat existing target files as overwrite-approved during review")
    services_review_result_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_review_result_parser.add_argument("--out")
    services_review_result_parser.set_defaults(func=command_services_review_result)
    services_review_results_parser = services_sub.add_parser("review-results", help="Review a directory of service-builder results")
    services_review_results_parser.add_argument("lab")
    services_review_results_parser.add_argument("--results", required=True, help="Directory containing *.result.yaml service result files")
    services_review_results_parser.add_argument("--force", action="store_true", help="Treat existing target files as overwrite-approved during review")
    services_review_results_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_review_results_parser.add_argument("--out")
    services_review_results_parser.set_defaults(func=command_services_review_results)
    services_apply_result_parser = services_sub.add_parser("apply-result", help="Apply a completed service-builder result to a service directory")
    services_apply_result_parser.add_argument("lab")
    services_apply_result_parser.add_argument("--result", required=True, help="Path to a service result YAML file")
    services_apply_result_parser.add_argument("--force", action="store_true", help="Overwrite existing files in the target service directory")
    services_apply_result_parser.add_argument("--dry-run", action="store_true", help="Validate and show what would be written without changing files")
    services_apply_result_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_apply_result_parser.add_argument("--out")
    services_apply_result_parser.set_defaults(func=command_services_apply_result)
    services_apply_results_parser = services_sub.add_parser("apply-results", help="Apply ready service-builder results from a directory")
    services_apply_results_parser.add_argument("lab")
    services_apply_results_parser.add_argument("--results", required=True, help="Directory containing *.result.yaml service result files")
    services_apply_results_parser.add_argument("--force", action="store_true", help="Overwrite existing files in target service directories")
    services_apply_results_parser.add_argument("--execute", action="store_true", help="Write files. Default is a dry-run.")
    services_apply_results_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_apply_results_parser.add_argument("--out")
    services_apply_results_parser.set_defaults(func=command_services_apply_results)
    services_scaffold_parser = services_sub.add_parser("scaffold", help="Create service artifact directories and hook placeholders")
    services_scaffold_parser.add_argument("lab")
    services_scaffold_parser.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    services_scaffold_parser.set_defaults(func=command_services_scaffold)
    services_materialize_parser = services_sub.add_parser("materialize", help="Create safe runnable placeholder service runtimes")
    services_materialize_parser.add_argument("lab")
    services_materialize_parser.add_argument("--force", action="store_true", help="Overwrite existing runtime placeholder files")
    services_materialize_parser.set_defaults(func=command_services_materialize)
    for hook_name in ("healthcheck", "reset"):
        hook_parser = services_sub.add_parser(hook_name, help=f"Run service {hook_name}.sh hooks")
        hook_parser.add_argument("lab")
        hook_parser.add_argument("--service", help="Run a single service hook")
        hook_parser.add_argument("--dry-run", action="store_true", help="Print hook targets without executing them")
        hook_parser.set_defaults(func=command_services_hook, hook=hook_name)

    qa_parser = sub.add_parser("qa", help="QA and smoke-test utilities")
    qa_sub = qa_parser.add_subparsers(dest="qa_command", required=True)
    qa_smoke_parser = qa_sub.add_parser("smoke", help="Run schema, service, and provider smoke checks")
    qa_smoke_parser.add_argument("lab")
    qa_smoke_parser.add_argument("--out", required=True)
    qa_smoke_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_smoke_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    qa_smoke_parser.add_argument("--materialize", action="store_true", help="Copy the lab and materialize placeholder runtimes before building")
    qa_smoke_parser.add_argument("--force", action="store_true", help="Overwrite generated QA working files")
    qa_smoke_parser.set_defaults(func=command_qa_smoke)
    qa_release_gate_parser = qa_sub.add_parser("release-gate", help="Run strict release readiness checks")
    qa_release_gate_parser.add_argument("lab")
    qa_release_gate_parser.add_argument("--out", required=True)
    qa_release_gate_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_release_gate_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    qa_release_gate_parser.add_argument("--materialize", action="store_true", help="Copy the lab and materialize placeholder runtimes before building")
    qa_release_gate_parser.add_argument("--force", action="store_true", help="Overwrite generated QA working files")
    qa_release_gate_parser.set_defaults(func=command_qa_release_gate)

    provider_parser = sub.add_parser("provider", help="Provider lifecycle utilities")
    provider_sub = provider_parser.add_subparsers(dest="provider_command", required=True)
    for action in ("deploy", "destroy", "status"):
        lifecycle_parser = provider_sub.add_parser(action, help=f"{action.title()} generated provider output")
        lifecycle_parser.add_argument("output", help="Generated provider output directory")
        lifecycle_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
        lifecycle_parser.add_argument("--execute", action="store_true", help="Execute the provider lifecycle command. Default is dry-run.")
        if action == "destroy":
            lifecycle_parser.add_argument("--volumes", action="store_true", help="Remove Docker Compose volumes during destroy")
        else:
            lifecycle_parser.add_argument("--volumes", action="store_false", help=argparse.SUPPRESS)
        lifecycle_parser.set_defaults(func=command_provider_lifecycle, lifecycle_action=action)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
