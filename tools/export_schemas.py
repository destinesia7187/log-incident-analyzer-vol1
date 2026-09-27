"""Export documented machine-readable contracts without network access."""

from pathlib import Path

from lia.common import write_json
from lia.config import Config, Manifest
from lia.schemas import SCHEMAS

root = Path(__file__).resolve().parents[1] / "schemas"
root.mkdir(exist_ok=True)
for name, schema in SCHEMAS.items():
    write_json(root / name.replace(".json", ".schema.json"), schema)
for name, model in [("config", Config), ("manifest", Manifest)]:
    write_json(root / f"{name}.schema.json", model.model_json_schema(by_alias=True))
