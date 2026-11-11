import json
from importlib.resources import files

from .models import Check, Report


def load_demo() -> Report:
    data = json.loads(files("upstreamlens").joinpath("demo.json").read_text(encoding="utf-8"))
    data["checks"] = [Check(**check) for check in data["checks"]]
    return Report(**data)
