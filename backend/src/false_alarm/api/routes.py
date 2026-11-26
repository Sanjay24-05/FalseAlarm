"""HTTP contract for alerts, scenarios, and investigations."""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict

from false_alarm.errors import AlertNotFound, ScenarioNotFound
from false_alarm.service import (
    alert_investigations,
    execute_investigation,
    get_alert_view,
    get_investigation,
    ingest_alert,
    list_alert_summaries,
    list_scenarios,
    load_scenario,
    start_investigation,
)

router = APIRouter()


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alert_id: str


@router.post("/alerts")
async def create_alert(request: Request) -> JSONResponse:
    raw = await request.body()
    if not raw or not raw.strip():
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "body", "message": "Request body is empty"}]},
        )
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "body", "message": "Request body is not valid JSON"}]},
        )
    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "body", "message": "Alert payload must be a JSON object"}]},
        )
    # Ingest reads and writes SQLite; run it on a worker thread so the event loop keeps serving.
    result = await run_in_threadpool(ingest_alert, payload)
    if result.errors:
        return JSONResponse(status_code=422, content={"errors": result.errors})
    return JSONResponse(status_code=result.status_code, content=result.public())


@router.post("/alerts/upload")
async def upload_alerts(file: UploadFile = File(...)) -> JSONResponse:
    raw = await file.read()
    if not raw or not raw.strip():
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "file", "message": "Upload is empty"}]},
        )
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "file", "message": "Upload is not valid JSON"}]},
        )
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        if not data:
            return JSONResponse(
                status_code=422,
                content={"errors": [{"field": "file", "message": "Upload contains no alerts"}]},
            )
        items = data
    else:
        return JSONResponse(
            status_code=422,
            content={"errors": [{"field": "file", "message": "Upload must be a JSON object or array"}]},
        )
    return JSONResponse(status_code=200, content={"results": await run_in_threadpool(_ingest_batch, items)})


def _ingest_batch(items: list) -> list[dict]:
    results = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            results.append(
                {"errors": [{"field": f"[{index}]", "message": "Alert payload must be a JSON object"}]}
            )
            continue
        result = ingest_alert(item)
        if result.errors:
            results.append({"errors": result.errors})
        else:
            results.append(result.public())
    return results


@router.get("/alerts")
def get_alerts() -> dict:
    return {"alerts": list_alert_summaries()}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    view = get_alert_view(alert_id)
    if view is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return view


@router.get("/alerts/{alert_id}/investigations")
def get_alert_investigations(alert_id: str) -> dict:
    investigations = alert_investigations(alert_id)
    if investigations is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"investigations": investigations}


@router.get("/scenarios")
def get_scenarios() -> dict:
    return {"scenarios": list_scenarios()}


@router.post("/scenarios/{scenario_id}/load")
def post_scenario(scenario_id: str) -> JSONResponse:
    try:
        result = load_scenario(scenario_id)
    except ScenarioNotFound:
        raise HTTPException(status_code=404, detail="Scenario not found") from None
    if result.errors:
        return JSONResponse(status_code=422, content={"errors": result.errors})
    return JSONResponse(status_code=result.status_code, content=result.public())


@router.post("/investigations")
def post_investigation(body: InvestigateRequest, background: BackgroundTasks) -> JSONResponse:
    try:
        started = start_investigation(body.alert_id)
    except AlertNotFound:
        raise HTTPException(status_code=404, detail="Alert not found") from None
    if started["created"]:
        background.add_task(execute_investigation, started["id"])
    return JSONResponse(status_code=202, content={"id": started["id"], "status": "running"})


@router.get("/investigations/{investigation_id}")
def get_investigation_view(investigation_id: str) -> dict:
    document = get_investigation(investigation_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return document
