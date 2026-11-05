from collections.abc import Generator
import logging
import socket
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

db_url = settings.database_url
connect_args = {}


def _is_db_reachable(url_str: str, timeout: float = 0.2) -> bool:
    """Quick socket probe to avoid 30-60s TCP connect timeout when PostgreSQL is not running."""
    try:
        parsed = urlparse(url_str.replace("postgresql+psycopg://", "http://").replace("postgresql://", "http://"))
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(db_url, connect_args=connect_args)
elif _is_db_reachable(db_url):
    engine = create_engine(db_url, pool_pre_ping=True)
else:
    # PostgreSQL is not running on host:port, fall back instantly to SQLite
    sqlite_url = "sqlite:///./cyber_analytics.db"
    logger.info("PostgreSQL is offline; using instant local SQLite database (%s)", sqlite_url)
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
