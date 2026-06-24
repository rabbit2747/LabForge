from __future__ import annotations

import argparse
from pathlib import Path

from .model import LabSpec
from .access_playtest import run_access_playtest
from .adapter_smoke import adapter_smoke_to_json, adapter_smoke_to_markdown, run_adapter_smoke
from .agent_adapters import AgentAdapterError, get_agent_adapter, render_agent_adapter_list
from .control_selection import apply_control_selection, render_control_catalog
from .doctor import inspect_host, report_to_json, report_to_markdown
from .e2e_solver import run_e2e_solver
from .design import (
    apply_design_fix_results,
    create_design_fix_tasks,
    create_design_fix_task_packages,
    create_design_workspace_from_prompt,
    render_fix_apply_report,
    render_fix_package_report,
    render_fix_result_review_report,
    render_fix_run_report,
    render_design_fix_tasks,
    render_design_review_report,
    review_design_fix_results,
    review_design_workspace,
    run_design_fix_task,
)
from .execution_plan import create_execution_plan, plan_to_json, plan_to_markdown
from .framework_guard import framework_guard_to_json, framework_guard_to_markdown, guard_framework_hooks
from .implementation_plan import (
    create_service_agent_packages,
    create_service_implementation_plan,
    implementation_plan_to_json,
    implementation_plan_to_markdown,
)
from .intake import create_intake_from_prompt, create_intake_template, normalize_prompt_text, scaffold_lab_from_intake
from .mvp_matrix import run_mvp_matrix
from .packaging import create_supervisor_package
from .pipeline import create_lab_pipeline, evaluate_pipeline_gate, pipeline_gate_to_markdown, pipeline_result_to_markdown
from .playtest import run_playtest
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
from .realism import check_realism, realism_profiles_to_markdown, realism_report_to_json, realism_report_to_markdown
from .render import build_lab, render_docs
from .schema import export_schemas
from .service_verification import service_verification_to_json, service_verification_to_markdown, verify_services
from .solver_runner import run_solver_plan
from .service_blueprints import (
    create_service_blueprints,
    inspect_service_implementation_status,
    service_blueprints_to_markdown,
    service_status_to_markdown,
)
from .studio import run_studio
from .service_templates import list_service_templates
from .vulnerability_plugins import list_vulnerability_plugins
from .vulnerability_scaffolds import SUPPORTED_VULNERABILITY_SCAFFOLDS
from .verified_mvp import write_verified_mvp_manifest
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


def command_guard_framework_hooks(args: argparse.Namespace) -> int:
    report = guard_framework_hooks(Path(args.root))
    if args.out:
        out = Path(args.out)
        write_text(out, framework_guard_to_json(report) if args.format == "json" else framework_guard_to_markdown(report))
        print(f"Rendered framework guard report: {out.resolve()}")
    elif args.format == "json":
        print(framework_guard_to_json(report))
    else:
        print(framework_guard_to_markdown(report))
    return 0 if report.status == "passed" else 1


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


def command_intake_from_prompt(args: argparse.Namespace) -> int:
    if args.prompt and args.prompt_file:
        print("Use either --prompt or --prompt-file, not both.")
        return 2
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8-sig")
    else:
        prompt = args.prompt or ""
    prompt = normalize_prompt_text(prompt)
    if not prompt.strip():
        print("A non-empty scenario prompt is required. Use --prompt or --prompt-file.")
        return 2
    written = create_intake_from_prompt(
        Path(args.out),
        prompt=prompt,
        lab_id=args.lab_id,
        title=args.title,
        industry=args.industry,
        difficulty=args.difficulty,
        provider=args.provider,
        force=args.force,
    )
    print(f"Created natural-language scenario intake package: {Path(args.out).resolve()}")
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


def command_design_from_prompt(args: argparse.Namespace) -> int:
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8-sig")
    else:
        prompt = args.prompt or ""
    prompt = normalize_prompt_text(prompt)
    if not prompt.strip():
        print("A non-empty scenario prompt is required. Use --prompt or --prompt-file.")
        return 2
    try:
        get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    result = create_design_workspace_from_prompt(
        Path(args.out),
        prompt=prompt,
        lab_id=args.lab_id,
        title=args.title,
        industry=args.industry,
        difficulty=args.difficulty,
        provider=args.provider,
        adapter=args.adapter,
        agent=args.agent,
        force=args.force,
    )
    print(f"Created LabForge design workspace: {Path(args.out).resolve()}")
    print(f"- intake: {Path(result.intake_dir).resolve()}")
    print(f"- lab: {Path(result.lab_dir).resolve()}")
    print(f"- agents: {Path(result.agent_workspace_dir).resolve()}")
    print(f"- summary: {(Path(args.out) / 'design-workspace-summary.md').resolve()}")
    if result.validation_errors:
        print("Agent workspace validation failed:")
        for error in result.validation_errors:
            print(f"- {error}")
        return 1
    return 0


def command_pipeline_create(args: argparse.Namespace) -> int:
    if args.prompt and args.prompt_file:
        print("Use either --prompt or --prompt-file, not both.")
        return 2
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8-sig")
    else:
        prompt = args.prompt or ""
    prompt = normalize_prompt_text(prompt)
    if not prompt.strip():
        print("A non-empty scenario prompt is required. Use --prompt or --prompt-file.")
        return 2
    result = create_lab_pipeline(
        Path(args.out),
        prompt=prompt,
        lab_id=args.lab_id,
        title=args.title,
        industry=args.industry,
        difficulty=args.difficulty,
        provider=args.provider,
        profile=args.profile,
        adapter=args.adapter,
        force=args.force,
        materialize=not args.no_materialize,
        package_service_agents=not args.no_service_agents,
    )
    if args.format == "json":
        print(result.model_dump_json(indent=2))
    else:
        print(pipeline_result_to_markdown(result))
    return 0 if result.status in {"complete", "warning"} else 1


def command_pipeline_gate(args: argparse.Namespace) -> int:
    report = evaluate_pipeline_gate(Path(args.workspace))
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(pipeline_gate_to_markdown(report))
    if args.strict and report.decision not in {"ready-for-supervisor", "release-candidate"}:
        return 1
    return 0


def command_pipeline_verified_mvp(args: argparse.Namespace) -> int:
    if args.prompt and args.prompt_file:
        print("Use either --prompt or --prompt-file, not both.")
        return 2
    if args.prompt_file:
        prompt = Path(args.prompt_file).read_text(encoding="utf-8-sig")
    else:
        prompt = args.prompt or ""
    prompt = normalize_prompt_text(prompt)
    if not prompt.strip():
        print("A non-empty scenario prompt is required. Use --prompt or --prompt-file.")
        return 2

    out = Path(args.out)
    result = create_lab_pipeline(
        out,
        prompt=prompt,
        lab_id=args.lab_id,
        title=args.title,
        industry=args.industry,
        difficulty=args.difficulty,
        provider=args.provider,
        profile=args.profile,
        adapter=args.adapter,
        force=args.force,
        materialize=not args.no_materialize,
        package_service_agents=not args.no_service_agents,
    )
    release_provider = args.release_provider or args.provider
    if release_provider == "auto":
        release_provider = "docker-compose"
    release_gate = run_release_gate(
        Path(result.lab_dir),
        out / "release-gate",
        provider=release_provider,
        profile=args.profile,
        materialize=not args.no_materialize,
        force=True,
        agent_result_dir=out / "agents" / ".ai" / "outputs",
    )
    from .studio import read_scenario_detail

    manifest = write_verified_mvp_manifest(out, read_scenario_detail(out.parent, out.name))
    if args.format == "json":
        print_json = {
            "pipeline": result.model_dump(),
            "release_gate": release_gate.model_dump(),
            "verified_mvp": manifest,
        }
        import json

        print(json.dumps(print_json, ensure_ascii=False, indent=2))
    else:
        print(f"Verified MVP status: {manifest.get('status')}")
        print(f"- workspace: {out.resolve()}")
        print(f"- manifest: {(out / 'mvp' / 'verified-mvp.md').resolve()}")
        print(f"- manifest_json: {(out / 'mvp' / 'verified-mvp.json').resolve()}")
        print(f"- release_gate: {release_gate.status}")
    return 0 if result.status in {"complete", "warning"} and release_gate.release_ready else 1


def command_design_review(args: argparse.Namespace) -> int:
    report = review_design_workspace(
        Path(args.workspace),
        out=Path(args.out) if args.out else None,
        industry=args.industry,
        force=args.force,
    )
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_design_review_report(report))
    return 0 if report.status != "failed" else 1


def command_design_tasks(args: argparse.Namespace) -> int:
    report = create_design_fix_tasks(
        Path(args.workspace),
        review_dir=Path(args.review_dir) if args.review_dir else None,
    )
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_design_fix_tasks(report))
    return 0 if report.status != "blocked" else 1


def command_design_package_tasks(args: argparse.Namespace) -> int:
    try:
        adapter = get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    report = create_design_fix_task_packages(
        Path(args.workspace),
        adapter=args.adapter,
        review_dir=Path(args.review_dir) if args.review_dir else None,
    )
    prepared = []
    if args.prepare:
        for package in report.packages:
            prepared.append(adapter.prepare(Path(package["package_file"])))
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_fix_package_report(report))
    for result in prepared:
        if result.invocation_file:
            print(f"- {result.invocation_file}")
    return 0


def command_design_run_task(args: argparse.Namespace) -> int:
    try:
        report = run_design_fix_task(
            Path(args.workspace),
            task_id=args.task,
            adapter=args.adapter,
            execute=args.execute,
            review_dir=Path(args.review_dir) if args.review_dir else None,
        )
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_fix_run_report(report))
    return 0 if report.status in {"prepared", "complete", "not-implemented"} else 1


def command_design_review_fix_results(args: argparse.Namespace) -> int:
    report = review_design_fix_results(
        Path(args.workspace),
        review_dir=Path(args.review_dir) if args.review_dir else None,
    )
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_fix_result_review_report(report))
    return 0 if report.status not in {"failed", "blocked"} else 1


def command_design_apply_fix_results(args: argparse.Namespace) -> int:
    report = apply_design_fix_results(
        Path(args.workspace),
        review_dir=Path(args.review_dir) if args.review_dir else None,
        task_id=args.task,
        execute=args.execute,
        force=args.force,
    )
    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_fix_apply_report(report))
    return 0 if report.status == "passed" else 1


def command_studio_serve(args: argparse.Namespace) -> int:
    run_studio(args.host, args.port, Path(args.workspace))
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
        agent_result_dir=Path(args.agent_results) if args.agent_results else None,
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


def command_realism_profiles(args: argparse.Namespace) -> int:
    print(realism_profiles_to_markdown())
    return 0


def command_realism_check(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = check_realism(spec, industry=args.industry, strict=args.strict)
    if args.out:
        out = Path(args.out)
        write_text(out, realism_report_to_json(report) if args.format == "json" else realism_report_to_markdown(report))
        print(f"Rendered realism report: {out.resolve()}")
    elif args.format == "json":
        print(realism_report_to_json(report))
    else:
        print(realism_report_to_markdown(report))
    return 0 if report.status != "failed" else 1


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
        if path.name == "run-plan.yaml" or not path.name.endswith(".package.yaml"):
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


def command_agents_smoke_adapters(args: argparse.Namespace) -> int:
    adapters = args.adapter or None
    report = run_adapter_smoke(
        Path(args.lab),
        Path(args.out),
        adapters=adapters,
        agent_id=args.agent,
        force=args.force,
    )
    if args.report:
        report_path = Path(args.report)
        write_text(report_path, adapter_smoke_to_json(report) if args.format == "json" else adapter_smoke_to_markdown(report))
        print(f"Rendered adapter smoke report: {report_path.resolve()}")
    elif args.format == "json":
        print(adapter_smoke_to_json(report))
    else:
        print(adapter_smoke_to_markdown(report))
    return 0 if report.status == "passed" else 1


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


def command_services_blueprints(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = create_service_blueprints(spec, Path(args.out) if args.out else None)
    if args.out:
        print(f"Rendered service blueprints: {Path(args.out).resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_blueprints_to_markdown(report))
    return 0


def command_services_status(args: argparse.Namespace) -> int:
    spec = LabSpec.load(Path(args.lab))
    report = inspect_service_implementation_status(spec, Path(args.out) if args.out else None)
    if args.out:
        print(f"Rendered service status: {Path(args.out).resolve()}")
    elif args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(service_status_to_markdown(report))
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


def command_services_run_agents(args: argparse.Namespace) -> int:
    try:
        adapter = get_agent_adapter(args.adapter)
    except AgentAdapterError as exc:
        print(str(exc))
        return 1
    if args.execute and not adapter.live_execution:
        print(f"Agent adapter `{args.adapter}` does not support live execution.")
        return 1

    root = Path(args.workspace).resolve()
    package_dir = root / ".ai" / "service-build"
    if not package_dir.exists():
        print(f"service-builder package directory not found: {package_dir}")
        return 1
    package_files = sorted(package_dir.glob("*.package.yaml"))
    if args.service:
        package_files = [
            path for path in package_files
            if args.service in path.stem or f"service-build-{args.service}" in path.stem
        ]
    if not package_files:
        print("no service-builder package files matched")
        return 1

    failed = []
    for package_file in package_files:
        if args.execute:
            result = adapter.execute(package_file)
            print(f"- {result.task_id}: {result.status} ({result.message})")
            if result.output_file:
                print(f"  output: {result.output_file}")
            if result.transcript_file:
                print(f"  transcript: {result.transcript_file}")
            if result.status != "complete":
                failed.append(result)
        else:
            result = adapter.prepare(package_file)
            print(f"- {result.task_id}: {result.status} ({result.message})")
            if result.invocation_file:
                print(f"  invocation: {result.invocation_file}")
            if result.status != "prepared":
                failed.append(result)
    return 1 if failed else 0


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
        "| Plugin | Scaffold | Compatible Templates | MITRE | Required Config | Description |",
        "|---|---|---|---|---|---|",
    ]
    for plugin in list_vulnerability_plugins():
        templates = ", ".join(f"`{item}`" for item in plugin.compatible_templates)
        mitre = ", ".join(f"`{item}`" for item in plugin.mitre_techniques)
        required = ", ".join(f"`{item}`" for item in plugin.required_config_keys) or "-"
        scaffold = "minimum-runnable" if plugin.plugin_id in SUPPORTED_VULNERABILITY_SCAFFOLDS else "contract-only"
        lines.append(f"| `{plugin.plugin_id}` | {scaffold} | {templates} | {mitre} | {required} | {plugin.description} |")
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
        agent_result_dir=Path(args.agent_results) if args.agent_results else None,
    )
    print(f"Release gate status: {report.status}")
    print(f"- {(Path(args.out) / 'release-gate-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'release-gate-report.yaml').resolve()}")
    return 0 if report.status == "passed" else 1


def command_qa_mvp_matrix(args: argparse.Namespace) -> int:
    report = run_mvp_matrix(
        Path(args.out),
        provider=args.provider,
        profile=args.profile,
        adapter=args.adapter,
        force=args.force,
    )
    print(f"MVP matrix status: {report.status}")
    for case in report.cases:
        print(f"- {case.case_id}: {case.status} ({case.pipeline_decision or '-'} / {case.release_gate_status or '-'})")
    print(f"- {(Path(args.out) / 'mvp-matrix-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'mvp-matrix-report.yaml').resolve()}")
    return 0 if report.status == "passed" else 1


def command_qa_playtest(args: argparse.Namespace) -> int:
    report = run_playtest(
        Path(args.lab),
        Path(args.out),
        provider=args.provider,
        profile=args.profile,
        materialize=args.materialize,
        force=args.force,
    )
    print(f"Playtest status: {report.status}")
    print(f"- {(Path(args.out) / 'playtest-report.md').resolve()}")
    print(f"- {(Path(args.out) / 'playtest-report.yaml').resolve()}")
    print(f"- {(Path(args.out) / 'learner-access.md').resolve()}")
    print(f"- {(Path(args.out) / 'learner-access.json').resolve()}")
    print(f"- {(Path(args.out) / 'access-playtest' / 'access-playtest.md').resolve()}")
    print(f"- {(Path(args.out) / 'solver-plan.md').resolve()}")
    print(f"- {(Path(args.out) / 'solver-plan.json').resolve()}")
    print(f"- {(Path(args.out) / 'solver-run' / 'solver-run.md').resolve()}")
    print(f"- {(Path(args.out) / 'playtest-walkthrough.md').resolve()}")
    return 0 if report.status in {"passed", "warning"} else 1


def command_qa_access_playtest(args: argparse.Namespace) -> int:
    report = run_access_playtest(
        Path(args.access_manifest),
        Path(args.out),
        execute=args.execute,
        timeout_seconds=args.timeout,
    )
    print(f"Access playtest status: {report.status}")
    print(f"- {(Path(args.out) / 'access-playtest.md').resolve()}")
    print(f"- {(Path(args.out) / 'access-playtest.yaml').resolve()}")
    print(f"- {(Path(args.out) / 'access-playtest.json').resolve()}")
    return 0 if report.status in {"planned", "passed", "warning"} else 1


def command_qa_solver_run(args: argparse.Namespace) -> int:
    report = run_solver_plan(
        Path(args.solver_plan),
        Path(args.out),
        access_manifest=Path(args.access_manifest) if args.access_manifest else None,
        endpoint_manifest=Path(args.endpoint_manifest) if args.endpoint_manifest else None,
        execute=args.execute,
        timeout_seconds=args.timeout,
    )
    print(f"Solver run status: {report.status}")
    print(f"- {(Path(args.out) / 'solver-run.md').resolve()}")
    print(f"- {(Path(args.out) / 'solver-run.yaml').resolve()}")
    print(f"- {(Path(args.out) / 'solver-run.json').resolve()}")
    return 0 if report.status in {"planned", "passed", "warning"} else 1


def command_qa_e2e_solver(args: argparse.Namespace) -> int:
    report = run_e2e_solver(
        Path(args.provider_output),
        Path(args.solver_plan),
        Path(args.access_manifest),
        Path(args.out),
        provider=args.provider,
        execute=args.execute,
        cleanup=args.cleanup,
        timeout_seconds=args.timeout,
    )
    print(f"E2E solver status: {report.status}")
    print(f"- {(Path(args.out) / 'e2e-solver.md').resolve()}")
    print(f"- {(Path(args.out) / 'e2e-solver.yaml').resolve()}")
    print(f"- {(Path(args.out) / 'e2e-solver.json').resolve()}")
    return 0 if report.status in {"planned", "passed", "warning"} else 1


def command_provider_lifecycle(args: argparse.Namespace) -> int:
    result = provider_lifecycle(
        Path(args.output),
        provider=args.provider,
        action=args.lifecycle_action,
        execute=args.execute,
        remove_volumes=args.volumes,
        timeout_seconds=args.timeout,
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

    guard_parser = sub.add_parser("guard", help="Run framework-level safety guards")
    guard_sub = guard_parser.add_subparsers(dest="guard_command", required=True)
    guard_hooks_parser = guard_sub.add_parser(
        "framework-hooks",
        help="Detect scenario-specific markers in LabForge framework code and templates",
    )
    guard_hooks_parser.add_argument("root", nargs="?", default=".")
    guard_hooks_parser.add_argument("--format", choices=["text", "json"], default="text")
    guard_hooks_parser.add_argument("--out")
    guard_hooks_parser.set_defaults(func=command_guard_framework_hooks)

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
    intake_from_prompt_parser = intake_sub.add_parser(
        "from-prompt",
        help="Create a scenario intake package from a natural-language prompt",
    )
    prompt_source = intake_from_prompt_parser.add_mutually_exclusive_group(required=True)
    prompt_source.add_argument("--prompt", help="Natural-language scenario prompt")
    prompt_source.add_argument("--prompt-file", help="Path to a file containing the scenario prompt")
    intake_from_prompt_parser.add_argument("--out", required=True)
    intake_from_prompt_parser.add_argument("--lab-id")
    intake_from_prompt_parser.add_argument("--title")
    intake_from_prompt_parser.add_argument("--industry", help="Optional target industry override")
    intake_from_prompt_parser.add_argument("--difficulty", default="intermediate")
    intake_from_prompt_parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "docker-compose", "hybrid", "ansible", "terraform", "ludus"],
    )
    intake_from_prompt_parser.add_argument("--force", action="store_true")
    intake_from_prompt_parser.set_defaults(func=command_intake_from_prompt)
    intake_scaffold_parser = intake_sub.add_parser("scaffold", help="Create a LabForge draft from scenario-intake.yaml")
    intake_scaffold_parser.add_argument("--from", dest="from_file", required=True)
    intake_scaffold_parser.add_argument("--out", required=True)
    intake_scaffold_parser.add_argument("--force", action="store_true")
    intake_scaffold_parser.set_defaults(func=command_intake_scaffold)

    pipeline_parser = sub.add_parser("pipeline", help="Run opinionated end-to-end scenario creation workflows")
    pipeline_sub = pipeline_parser.add_subparsers(dest="pipeline_command", required=True)
    pipeline_create_parser = pipeline_sub.add_parser(
        "create",
        help="Create intake, draft lab, reviews, service blueprints, service scaffolds, and workflow reports from natural language",
    )
    pipeline_prompt_source = pipeline_create_parser.add_mutually_exclusive_group(required=True)
    pipeline_prompt_source.add_argument("--prompt", help="Natural-language scenario prompt")
    pipeline_prompt_source.add_argument("--prompt-file", help="Path to a file containing the scenario prompt")
    pipeline_create_parser.add_argument("--out", required=True)
    pipeline_create_parser.add_argument("--lab-id")
    pipeline_create_parser.add_argument("--title")
    pipeline_create_parser.add_argument("--industry", help="Optional target industry override")
    pipeline_create_parser.add_argument("--difficulty", default="intermediate")
    pipeline_create_parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "docker-compose", "hybrid", "ansible", "terraform", "ludus"],
    )
    pipeline_create_parser.add_argument("--profile", default="protected", choices=["unprotected", "protected"])
    pipeline_create_parser.add_argument("--adapter", default="manual")
    pipeline_create_parser.add_argument("--no-materialize", action="store_true", help="Skip safe runtime materialization")
    pipeline_create_parser.add_argument("--no-service-agents", action="store_true", help="Skip service-builder package generation")
    pipeline_create_parser.add_argument("--format", choices=["text", "json"], default="text")
    pipeline_create_parser.add_argument("--force", action="store_true")
    pipeline_create_parser.set_defaults(func=command_pipeline_create)
    pipeline_gate_parser = pipeline_sub.add_parser(
        "gate",
        help="Evaluate whether a pipeline workspace is draft, blocked, ready for supervisor, or release-candidate",
    )
    pipeline_gate_parser.add_argument("workspace")
    pipeline_gate_parser.add_argument("--format", choices=["text", "json"], default="text")
    pipeline_gate_parser.add_argument("--strict", action="store_true", help="Return non-zero unless the workspace is ready for supervisor or release gate")
    pipeline_gate_parser.set_defaults(func=command_pipeline_gate)
    pipeline_verified_parser = pipeline_sub.add_parser(
        "verified-mvp",
        help="Create a natural-language pipeline workspace and run the strict release gate in one command",
    )
    pipeline_verified_prompt_source = pipeline_verified_parser.add_mutually_exclusive_group(required=True)
    pipeline_verified_prompt_source.add_argument("--prompt", help="Natural-language scenario prompt")
    pipeline_verified_prompt_source.add_argument("--prompt-file", help="Path to a file containing the scenario prompt")
    pipeline_verified_parser.add_argument("--out", required=True)
    pipeline_verified_parser.add_argument("--lab-id")
    pipeline_verified_parser.add_argument("--title")
    pipeline_verified_parser.add_argument("--industry", help="Optional target industry override")
    pipeline_verified_parser.add_argument("--difficulty", default="intermediate")
    pipeline_verified_parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "docker-compose", "hybrid", "ansible", "terraform", "ludus"],
    )
    pipeline_verified_parser.add_argument("--release-provider", default="", choices=["", "docker-compose", "hybrid", "ansible", "terraform", "ludus"])
    pipeline_verified_parser.add_argument("--profile", default="protected", choices=["unprotected", "protected"])
    pipeline_verified_parser.add_argument("--adapter", default="manual")
    pipeline_verified_parser.add_argument("--no-materialize", action="store_true", help="Skip safe runtime materialization")
    pipeline_verified_parser.add_argument("--no-service-agents", action="store_true", help="Skip service-builder package generation")
    pipeline_verified_parser.add_argument("--format", choices=["text", "json"], default="text")
    pipeline_verified_parser.add_argument("--force", action="store_true")
    pipeline_verified_parser.set_defaults(func=command_pipeline_verified_mvp)

    design_parser = sub.add_parser("design", help="Create design workspaces from scenario intent")
    design_sub = design_parser.add_subparsers(dest="design_command", required=True)
    design_from_prompt_parser = design_sub.add_parser(
        "from-prompt",
        help="Create intake, draft lab, agent workspace, and dry-run packages from natural language",
    )
    design_prompt_source = design_from_prompt_parser.add_mutually_exclusive_group(required=True)
    design_prompt_source.add_argument("--prompt", help="Natural-language scenario prompt")
    design_prompt_source.add_argument("--prompt-file", help="Path to a file containing the scenario prompt")
    design_from_prompt_parser.add_argument("--out", required=True)
    design_from_prompt_parser.add_argument("--lab-id")
    design_from_prompt_parser.add_argument("--title")
    design_from_prompt_parser.add_argument("--industry", help="Optional target industry override")
    design_from_prompt_parser.add_argument("--difficulty", default="intermediate")
    design_from_prompt_parser.add_argument(
        "--provider",
        default="auto",
        choices=["auto", "docker-compose", "hybrid", "ansible", "terraform", "ludus"],
    )
    design_from_prompt_parser.add_argument("--adapter", default="manual")
    design_from_prompt_parser.add_argument("--agent", help="Optional single agent id for generated execution packages")
    design_from_prompt_parser.add_argument("--force", action="store_true")
    design_from_prompt_parser.set_defaults(func=command_design_from_prompt)
    design_review_parser = design_sub.add_parser("review", help="Review a generated design workspace")
    design_review_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_review_parser.add_argument("--out", help="Directory for review reports. Defaults to <workspace>/review")
    design_review_parser.add_argument("--industry", help="Override target industry for realism pre-check")
    design_review_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_review_parser.add_argument("--force", action="store_true")
    design_review_parser.set_defaults(func=command_design_review)
    design_tasks_parser = design_sub.add_parser("tasks", help="Convert design review findings into fix tasks")
    design_tasks_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_tasks_parser.add_argument("--review-dir", help="Review directory containing design-review-report.yaml")
    design_tasks_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_tasks_parser.set_defaults(func=command_design_tasks)
    design_package_tasks_parser = design_sub.add_parser("package-tasks", help="Create agent execution packages for design fix tasks")
    design_package_tasks_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_package_tasks_parser.add_argument("--review-dir", help="Review directory containing design-fix-tasks.yaml")
    design_package_tasks_parser.add_argument("--adapter", default="manual")
    design_package_tasks_parser.add_argument("--prepare", action="store_true", help="Also create adapter-specific invocation files")
    design_package_tasks_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_package_tasks_parser.set_defaults(func=command_design_package_tasks)
    design_run_task_parser = design_sub.add_parser("run-task", help="Prepare or execute one packaged design fix task")
    design_run_task_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_run_task_parser.add_argument("--task", required=True, help="Fix task id, for example fix-001")
    design_run_task_parser.add_argument("--review-dir", help="Review directory containing fix-agent-packages")
    design_run_task_parser.add_argument("--adapter", default="manual")
    design_run_task_parser.add_argument("--execute", action="store_true", help="Call the live adapter instead of only preparing an invocation")
    design_run_task_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_run_task_parser.set_defaults(func=command_design_run_task)
    design_review_fix_results_parser = design_sub.add_parser("review-fix-results", help="Review agent outputs for packaged design fix tasks")
    design_review_fix_results_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_review_fix_results_parser.add_argument("--review-dir", help="Review directory containing fix-agent-results")
    design_review_fix_results_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_review_fix_results_parser.set_defaults(func=command_design_review_fix_results)
    design_apply_fix_results_parser = design_sub.add_parser("apply-fix-results", help="Apply approved design fix result artifacts to the draft lab")
    design_apply_fix_results_parser.add_argument("workspace", help="Directory created by `labforge design from-prompt`")
    design_apply_fix_results_parser.add_argument("--review-dir", help="Review directory containing fix-agent-results")
    design_apply_fix_results_parser.add_argument("--task", help="Apply only one fix task id, for example fix-001")
    design_apply_fix_results_parser.add_argument("--execute", action="store_true", help="Write files. Default is a dry-run.")
    design_apply_fix_results_parser.add_argument("--force", action="store_true", help="Allow overwriting existing lab files after supervisor approval")
    design_apply_fix_results_parser.add_argument("--format", choices=["text", "json"], default="text")
    design_apply_fix_results_parser.set_defaults(func=command_design_apply_fix_results)

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
        workflow_command_parser.add_argument("--agent-results", help="Directory containing agent *.result.yaml files, including industry realism reviewer output")
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

    realism_parser = sub.add_parser("realism", help="Industry realism profile and validation utilities")
    realism_sub = realism_parser.add_subparsers(dest="realism_command", required=True)
    realism_profiles_parser = realism_sub.add_parser("profiles", help="List built-in industry realism profiles")
    realism_profiles_parser.set_defaults(func=command_realism_profiles)
    realism_check_parser = realism_sub.add_parser("check", help="Check whether a lab feels like the selected industry")
    realism_check_parser.add_argument("lab")
    realism_check_parser.add_argument("--industry", help="Industry profile to use, e.g. securities")
    realism_check_parser.add_argument("--strict", action="store_true", help="Fail when required industry capabilities are missing")
    realism_check_parser.add_argument("--format", choices=["text", "json"], default="text")
    realism_check_parser.add_argument("--out")
    realism_check_parser.set_defaults(func=command_realism_check)

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
    agents_smoke_parser = agents_sub.add_parser("smoke-adapters", help="Smoke-test agent adapters without live LLM calls")
    agents_smoke_parser.add_argument("lab")
    agents_smoke_parser.add_argument("--out", required=True, help="Temporary agent workspace output directory")
    agents_smoke_parser.add_argument("--adapter", action="append", help="Adapter to test. Can be repeated. Defaults to all adapters.")
    agents_smoke_parser.add_argument("--agent", default="scenario-designer", help="Agent id used for package generation")
    agents_smoke_parser.add_argument("--force", action="store_true", help="Replace the smoke workspace output directory")
    agents_smoke_parser.add_argument("--format", choices=["text", "json"], default="text")
    agents_smoke_parser.add_argument("--report", help="Write the smoke report to a file")
    agents_smoke_parser.set_defaults(func=command_agents_smoke_adapters)
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
    services_blueprints_parser = services_sub.add_parser("blueprints", help="Create service builder blueprints for each service artifact")
    services_blueprints_parser.add_argument("lab")
    services_blueprints_parser.add_argument("--out")
    services_blueprints_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_blueprints_parser.set_defaults(func=command_services_blueprints)
    services_status_parser = services_sub.add_parser("status", help="Report blueprint, scaffold, runtime, and test status for service implementations")
    services_status_parser.add_argument("lab")
    services_status_parser.add_argument("--out")
    services_status_parser.add_argument("--format", choices=["text", "json"], default="text")
    services_status_parser.set_defaults(func=command_services_status)
    services_agent_packages_parser = services_sub.add_parser("agent-packages", help="Create per-service service-builder agent packages")
    services_agent_packages_parser.add_argument("lab")
    services_agent_packages_parser.add_argument("--out", required=True)
    services_agent_packages_parser.add_argument("--adapter", default="manual")
    services_agent_packages_parser.set_defaults(func=command_services_agent_packages)
    services_run_agents_parser = services_sub.add_parser("run-agents", help="Prepare or execute service-builder agent packages")
    services_run_agents_parser.add_argument("workspace", help="Output directory created by services agent-packages")
    services_run_agents_mode = services_run_agents_parser.add_mutually_exclusive_group()
    services_run_agents_mode.add_argument("--dry-run", action="store_true", help="Prepare adapter handoff files without calling an LLM. This is the default.")
    services_run_agents_mode.add_argument("--execute", action="store_true", help="Call the selected live adapter and write service result files.")
    services_run_agents_parser.add_argument("--adapter", default="manual")
    services_run_agents_parser.add_argument("--service", help="Only run packages matching one service name")
    services_run_agents_parser.set_defaults(func=command_services_run_agents)
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
    services_scaffold_parser = services_sub.add_parser("scaffold", help="Create service artifact directories and implementation contracts")
    services_scaffold_parser.add_argument("lab")
    services_scaffold_parser.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    services_scaffold_parser.set_defaults(func=command_services_scaffold)
    services_materialize_parser = services_sub.add_parser("materialize", help="Create safe scenario-derived MVP service runtimes")
    services_materialize_parser.add_argument("lab")
    services_materialize_parser.add_argument("--force", action="store_true", help="Overwrite existing generated runtime files")
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
    qa_smoke_parser.add_argument("--materialize", action="store_true", help="Copy the lab and materialize MVP runtimes before building")
    qa_smoke_parser.add_argument("--force", action="store_true", help="Overwrite generated QA working files")
    qa_smoke_parser.set_defaults(func=command_qa_smoke)
    qa_release_gate_parser = qa_sub.add_parser("release-gate", help="Run strict release readiness checks")
    qa_release_gate_parser.add_argument("lab")
    qa_release_gate_parser.add_argument("--out", required=True)
    qa_release_gate_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_release_gate_parser.add_argument("--profile", default="unprotected", choices=["unprotected", "protected"])
    qa_release_gate_parser.add_argument("--materialize", action="store_true", help="Copy the lab and materialize MVP runtimes before building")
    qa_release_gate_parser.add_argument("--agent-results", help="Directory containing agent *.result.yaml files, including industry realism reviewer output")
    qa_release_gate_parser.add_argument("--force", action="store_true", help="Overwrite generated QA working files")
    qa_release_gate_parser.set_defaults(func=command_qa_release_gate)
    qa_mvp_matrix_parser = qa_sub.add_parser(
        "mvp-matrix",
        help="Run the natural-language to release-gate MVP matrix across built-in industry profiles",
    )
    qa_mvp_matrix_parser.add_argument("--out", required=True)
    qa_mvp_matrix_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_mvp_matrix_parser.add_argument("--profile", default="protected", choices=["unprotected", "protected"])
    qa_mvp_matrix_parser.add_argument("--adapter", default="manual")
    qa_mvp_matrix_parser.add_argument("--force", action="store_true", help="Replace the matrix output directory")
    qa_mvp_matrix_parser.set_defaults(func=command_qa_mvp_matrix)
    qa_playtest_parser = qa_sub.add_parser("playtest", help="Generate learner access and playtest evidence from generated lab output")
    qa_playtest_parser.add_argument("lab")
    qa_playtest_parser.add_argument("--out", required=True)
    qa_playtest_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_playtest_parser.add_argument("--profile", default="protected", choices=["unprotected", "protected"])
    qa_playtest_parser.add_argument("--materialize", action="store_true", help="Copy the lab and materialize MVP runtimes before playtesting")
    qa_playtest_parser.add_argument("--force", action="store_true", help="Overwrite generated playtest working files")
    qa_playtest_parser.set_defaults(func=command_qa_playtest)
    qa_access_playtest_parser = qa_sub.add_parser("access-playtest", help="Plan or execute browser/terminal access checks from learner-access.json")
    qa_access_playtest_parser.add_argument("access_manifest", help="Path to generated playtest/learner-access.json")
    qa_access_playtest_parser.add_argument("--out", required=True)
    qa_access_playtest_parser.add_argument("--execute", action="store_true", help="Actually run curl/ssh access checks. Default is dry-run.")
    qa_access_playtest_parser.add_argument("--timeout", type=int, default=5, help="Per-check timeout in seconds when --execute is used.")
    qa_access_playtest_parser.set_defaults(func=command_qa_access_playtest)
    qa_solver_run_parser = qa_sub.add_parser("solver-run", help="Plan or execute solver-agent checks from solver-plan.json")
    qa_solver_run_parser.add_argument("solver_plan", help="Path to generated playtest/solver-plan.json")
    qa_solver_run_parser.add_argument("--out", required=True)
    qa_solver_run_parser.add_argument("--access-manifest", help="Optional path to playtest/learner-access.json")
    qa_solver_run_parser.add_argument("--endpoint-manifest", help="Optional path to generated provider endpoints.json")
    qa_solver_run_parser.add_argument("--execute", action="store_true", help="Probe browser/SSH access where supported. Default is dry-run.")
    qa_solver_run_parser.add_argument("--timeout", type=int, default=5, help="Per-check timeout in seconds when --execute is used.")
    qa_solver_run_parser.set_defaults(func=command_qa_solver_run)
    qa_e2e_solver_parser = qa_sub.add_parser("e2e-solver", help="Validate/start provider output and run access plus solver probes")
    qa_e2e_solver_parser.add_argument("provider_output", help="Generated provider output directory")
    qa_e2e_solver_parser.add_argument("--solver-plan", required=True, help="Path to generated playtest/solver-plan.json")
    qa_e2e_solver_parser.add_argument("--access-manifest", required=True, help="Path to generated playtest/learner-access.json")
    qa_e2e_solver_parser.add_argument("--out", required=True)
    qa_e2e_solver_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
    qa_e2e_solver_parser.add_argument("--execute", action="store_true", help="Actually run provider lifecycle and access probes. Default is dry-run.")
    qa_e2e_solver_parser.add_argument("--cleanup", action="store_true", help="Stop provider output after solver probes.")
    qa_e2e_solver_parser.add_argument("--timeout", type=int, default=60, help="Provider lifecycle timeout in seconds when --execute is used.")
    qa_e2e_solver_parser.set_defaults(func=command_qa_e2e_solver)

    provider_parser = sub.add_parser("provider", help="Provider lifecycle utilities")
    provider_sub = provider_parser.add_subparsers(dest="provider_command", required=True)
    for action in ("validate", "deploy", "destroy", "status"):
        lifecycle_parser = provider_sub.add_parser(action, help=f"{action.title()} generated provider output")
        lifecycle_parser.add_argument("output", help="Generated provider output directory")
        lifecycle_parser.add_argument("--provider", default="docker-compose", choices=list_providers())
        lifecycle_parser.add_argument("--execute", action="store_true", help="Execute the provider lifecycle command. Default is dry-run.")
        lifecycle_parser.add_argument("--timeout", type=int, default=60, help="Execution timeout in seconds when --execute is used.")
        if action == "destroy":
            lifecycle_parser.add_argument("--volumes", action="store_true", help="Remove Docker Compose volumes during destroy")
        else:
            lifecycle_parser.add_argument("--volumes", action="store_false", help=argparse.SUPPRESS)
        lifecycle_parser.set_defaults(func=command_provider_lifecycle, lifecycle_action=action)

    studio_parser = sub.add_parser("studio", help="Run the LabForge Studio web UI")
    studio_sub = studio_parser.add_subparsers(dest="studio_command", required=True)
    studio_serve_parser = studio_sub.add_parser("serve", help="Start the local LabForge Studio server")
    studio_serve_parser.add_argument("--workspace", default="output/studio", help="Directory where Studio stores scenario workspaces")
    studio_serve_parser.add_argument("--host", default="127.0.0.1")
    studio_serve_parser.add_argument("--port", type=int, default=8765)
    studio_serve_parser.set_defaults(func=command_studio_serve)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
