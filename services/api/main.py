import logging

from fastapi import FastAPI

from core.settings import get_settings
from routers.health import router as health_router


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

    app = FastAPI(
        title="MLSEC Platform API",
        version="0.1.0",
    )

    app.include_router(health_router)
    return app


app = create_app()
