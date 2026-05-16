import logging
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.core.config import settings

# Structured Logging
logger = logging.getLogger("safeguard.db")

DATABASE_URL = settings.DATABASE_URL or "sqlite:///./safeguard_ai.db"
if not settings.DATABASE_URL:
    logger.info("No DATABASE_URL configured. Falling back to local SQLite at ./safeguard_ai.db.")

parsed_url = make_url(DATABASE_URL)
connect_args = {}
engine_kwargs = {"pool_pre_ping": True}

if parsed_url.drivername.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    engine_kwargs["connect_args"] = connect_args
    engine = create_engine(DATABASE_URL, **engine_kwargs)
else:
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 1800,
    })
    engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session Factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Declarative Base for Models
Base = declarative_base()

def verify_connection() -> bool:
    """Startup check for database connectivity."""
    try:
        with engine.connect() as conn:
            logger.info("Successfully connected to the database.")
            return True
    except Exception as e:
        logger.critical(f"Database connection failed: {str(e)}")
        return False
