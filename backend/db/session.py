from typing import Generator
from contextlib import contextmanager
from backend.db.database import SessionLocal

def get_db() -> Generator:
    """FastAPI Dependency for request-scoped database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def transaction_scope() -> Generator:
    """Context manager for background tasks and multi-step transactions."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
