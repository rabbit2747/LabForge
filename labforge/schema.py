from __future__ import annotations

import json
from pathlib import Path

from .io import write_text
from .agent_adapters import ADAPTER_SCHEMA_MODELS
from .agent_orchestration import AGENT_SCHEMA_MODELS
from .intake import INTAKE_SCHEMA_MODELS
from .linting import LINT_SCHEMA_MODELS
from .packaging import PACKAGE_SCHEMA_MODELS
from .provider_lifecycle import PROVIDER_LIFECYCLE_SCHEMA_MODELS
from .qa import QA_SCHEMA_MODELS
from .spec_models import SCHEMA_MODELS


def export_schemas(out: Path) -> list[Path]:
    written: list[Path] = []
    for filename, model in {
        **SCHEMA_MODELS,
        **AGENT_SCHEMA_MODELS,
        **ADAPTER_SCHEMA_MODELS,
        **INTAKE_SCHEMA_MODELS,
        **QA_SCHEMA_MODELS,
        **PROVIDER_LIFECYCLE_SCHEMA_MODELS,
        **LINT_SCHEMA_MODELS,
        **PACKAGE_SCHEMA_MODELS,
    }.items():
        schema = model.model_json_schema()
        target = out / filename
        write_text(target, json.dumps(schema, ensure_ascii=False, indent=2) + "\n")
        written.append(target)
    return written
