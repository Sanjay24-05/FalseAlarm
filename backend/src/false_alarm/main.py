"""FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from false_alarm.api.routes import router
from false_alarm.agent.loop import recover_interrupted
from false_alarm.db import init_db
from false_alarm.security import RequestGuard
from false_alarm.settings import get_settings


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    init_db()
    recover_interrupted()
    yield


async def _validation_errors(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """Report framework validation in the same shape as alert validation."""
    errors = [
        {"field": ".".join(str(part) for part in item["loc"] if part != "body") or "body", "message": item["msg"]}
        for item in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"errors": errors})


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(title="False Alarm", lifespan=_lifespan)
    # The last middleware added runs first: Host check, then CORS (which answers preflights), then the guard.
    application.add_middleware(
        RequestGuard, allowed_origins=settings.allowed_origins, api_token=settings.api_token
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    application.add_exception_handler(RequestValidationError, _validation_errors)
    application.include_router(router, prefix="/api")
    return application


app = create_app()


def run() -> None:
    uvicorn.run("false_alarm.main:app", host="127.0.0.1", port=8000)
