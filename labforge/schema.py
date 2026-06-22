from __future__ import annotations

import json
from pathlib import Path

from .io import write_text
from .spec_models import SCHEMA_MODELS


def export_schemas(out: Path) -> list[Path]:
    written: list[Path] = []
    for filename, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema()
        target = out / filename
        write_text(target, json.dumps(schema, ensure_ascii=False, indent=2) + "\n")
        written.append(target)
    return written

