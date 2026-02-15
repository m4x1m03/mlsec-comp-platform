import os
from functools import lru_cache

from sqlalchemy import create_engine, text  # type: ignore
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.settings import get_settings

# TODO: Change this to .env for resolving password, port, etc.
DEFAULT_DATABASE_URL = "postgresql://postgres:password123@postgres:5432/mlsec"


def get_database_url() -> str:
    settings = get_settings()
    return settings.database_url or os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return create_engine(get_database_url(), pool_pre_ping=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ping_db() -> bool:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
