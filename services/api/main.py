import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.settings import get_settings
from routers.admin import router as admin_router
from routers.auth import router as auth_router
from routers.health import router as health_router
from routers.leaderboard import router as leaderboard_router, start_redis_subscriber
from routers.queue import router as queue_router
from routers.submissions import router as submissions_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    from core.storage import ensure_bucket_exists

    logger = logging.getLogger(__name__)
    logger.info("Initializing API startup tasks...")

    try:
        logger.info("Ensuring MinIO bucket exists...")
        ensure_bucket_exists()
        logger.info("MinIO bucket ready")
    except Exception as e:
        logger.error(f"Failed to initialize MinIO: {e}")
        # Continue startup (may fail later on upload, but allows API to start)

    subscriber_task = asyncio.create_task(start_redis_subscriber())

    yield  # Application runs here

    subscriber_task.cancel()
    try:
        await subscriber_task
    except (asyncio.CancelledError, Exception):
        pass
    logger.info("API shutting down...")


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=getattr(
        logging, settings.log_level.upper(), logging.INFO))

    app = FastAPI(
        title="MLSEC Platform API",
        version="0.1.0",
        lifespan=lifespan,
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
    app.include_router(submissions_router, prefix="/api")
    app.include_router(leaderboard_router)
    app.include_router(admin_router)
    return app


app = create_app()
