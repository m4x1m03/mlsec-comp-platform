import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.settings import get_settings
from routers.auth import router as auth_router
from routers.health import router as health_router
from routers.queue import router as queue_router
from routers.submissions import router as submissions_router


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

    app = FastAPI(
        title="MLSEC Platform API",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(queue_router)
    app.include_router(submissions_router)
    return app


app = create_app()
