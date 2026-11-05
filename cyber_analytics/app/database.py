from collections.abc import Generator
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

db_url = settings.database_url
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(db_url, connect_args=connect_args)
else:
    try:
        engine = create_engine(db_url, pool_pre_ping=True)
        # Attempt lightweight probe to verify PostgreSQL is online
        with engine.connect():
            pass
    except Exception:
        # Fall back to local SQLite database when external PostgreSQL is not running
        sqlite_url = "sqlite:///./cyber_analytics.db"
        logger.warning(
            "Could not connect to PostgreSQL at %s; falling back to local SQLite database (%s)",
            db_url,
            sqlite_url,
        )
        engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
