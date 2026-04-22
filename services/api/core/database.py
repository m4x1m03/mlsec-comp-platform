"""Database connectivity helpers for the API service.

Defines the SQLAlchemy engine/session factory and convenience utilities for
dependency injection and health checks.
"""

import os
import logging
from functools import lru_cache

from sqlalchemy import create_engine, text  # type: ignore
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

from core.settings import get_settings

DEFAULT_DATABASE_URL = "postgresql://mlsec2:mlsec2_pw@postgres:5432/mlsec"
logger = logging.getLogger(__name__)


def get_database_url() -> str:
    """Resolve the database URL from settings or environment."""
    settings = get_settings()
    return settings.database_url or os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Create (and cache) the SQLAlchemy Engine."""
    logger.info("Creating database engine")
    return create_engine(get_database_url(), pool_pre_ping=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())

Base = declarative_base()


def get_db():
    """Yield a database session for FastAPI dependencies."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ping_db() -> bool:
    """Return True when a simple database query succeeds."""
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning("Database ping failed", exc_info=exc)
        return False
