# Database Connection
from sqlalchemy import create_engine # type: ignore
from sqlalchemy.orm import sessionmaker, declarative_base # type: ignore
import os

# TODO: Move this to a config file or environment variable
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:password123@postgres:5432/mlsec"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
