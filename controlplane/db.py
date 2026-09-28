"""Database setup. SQLite by default; any SQLAlchemy URL works (e.g. postgresql+psycopg://...)."""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

DEFAULT_URL = "sqlite:///./controlplane.db"


class Base(DeclarativeBase):
    pass


def make_engine(url: str | None = None) -> Engine:
    url = url or os.environ.get("CONTROLPLANE_DB_URL", DEFAULT_URL)
    kw: dict = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kw["poolclass"] = StaticPool   # one shared in-memory DB (tests)
    return create_engine(url, **kw)


def make_sessionmaker(engine: Engine) -> sessionmaker:
    from . import models  # noqa: F401  (register tables)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
