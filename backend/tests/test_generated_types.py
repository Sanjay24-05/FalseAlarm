"""The console's API types are generated from the backend models and must not drift from them."""

import importlib.util
from pathlib import Path

from fastapi.testclient import TestClient

from false_alarm.main import create_app

ROOT = Path(__file__).resolve().parents[2]
GENERATED = ROOT / "frontend" / "src" / "generated" / "api.ts"
SCRIPT = ROOT / "backend" / "scripts" / "generate_types.py"


def _generator():
    spec = importlib.util.spec_from_file_location("generate_types", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_types_match_the_backend_models():
    expected = _generator().render()
    assert GENERATED.exists(), "Run: python backend/scripts/generate_types.py"
    actual = GENERATED.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert actual == expected, "frontend/src/generated/api.ts is stale. Run: python backend/scripts/generate_types.py"


def test_the_types_cover_every_response_the_console_reads():
    text = _generator().render()
    for name in (
        "AlertSummary",
        "AlertList",
        "AlertView",
        "IngestResponse",
        "UploadResponse",
        "ScenarioList",
        "InvestigationStarted",
        "InvestigationList",
        "InvestigationDocument",
        "FieldErrors",
    ):
        assert f"export interface {name} " in text, name


def test_nullable_and_literal_fields_are_typed():
    text = _generator().render()
    assert "username: string | null;" in text
    assert 'verdict: "likely_benign" | "suspicious" | "confirmed_threat" | null;' in text


def test_every_api_route_declares_its_response_model():
    schema = TestClient(create_app()).get("/openapi.json").json()
    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            success = next(code for code in operation["responses"] if code.startswith("2"))
            content = operation["responses"][success].get("content", {}).get("application/json", {})
            assert "$ref" in str(content.get("schema", {})), f"{method.upper()} {path} has no response model"
