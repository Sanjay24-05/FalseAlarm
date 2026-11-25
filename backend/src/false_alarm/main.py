"""FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from false_alarm.api.routes import router
from false_alarm.db import init_db


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    init_db()
    yield


async def _validation_errors(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """Report framework validation in the same shape as alert validation."""
    errors = [
        {"field": ".".join(str(part) for part in item["loc"] if part != "body") or "body", "message": item["msg"]}
        for item in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"errors": errors})


def create_app() -> FastAPI:
    application = FastAPI(title="False Alarm", lifespan=_lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_exception_handler(RequestValidationError, _validation_errors)
    application.include_router(router, prefix="/api")
    return application


app = create_app()


def run() -> None:
    uvicorn.run("false_alarm.main:app", host="127.0.0.1", port=8000)
