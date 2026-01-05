# src/database.py
import logging
from typing import Optional, Dict
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import event
from src.config import get_settings

# ── 설정/로그 ────────────────────────────────────────────────────────────────
config = get_settings()
logging.basicConfig(level=config.logging_level)
logger = logging.getLogger(__name__)

# ── SQLAlchemy Base ──────────────────────────────────────────────────────────
Base = declarative_base()

# ── 엔진/세션메이커 캐시 ────────────────────────────────────────────────────
_ENGINE_CACHE: Dict[str, "AsyncEngine"] = {}
_SESSIONMAKER_CACHE: Dict[str, sessionmaker] = {}


def _service_dsn(service: Optional[str] = None) -> str:
    """
    설정에서 서비스명으로 DSN을 가져오고, 비동기 드라이버(aiomysql)로 교체.
    """
    dsn = config.get_database_url(service or config.database_service)
    if dsn.startswith("mysql+pymysql://"):
        dsn = dsn.replace("mysql+pymysql://", "mysql+aiomysql://", 1)
    return dsn


def get_engine(service: Optional[str] = None):
    """
    서비스명별 AsyncEngine을 생성/캐시하여 반환합니다.
    - aiomysql은 time_zone 인자를 직접 지원하지 않으므로,
      event 리스너를 통해 연결 시점에 SET time_zone 실행.
    """
    dsn = _service_dsn(service)
    if dsn not in _ENGINE_CACHE:
        logger.debug(
            f"[DB] Creating async engine for service='{service or config.database_service}' DSN='{dsn}'"
        )

        engine = create_async_engine(
            dsn,
            pool_pre_ping=True,
            pool_size=20,
            max_overflow=10,
            pool_timeout=20,
            pool_recycle=1800,
            future=True,
        )

        # ✅ 연결 직후 타임존 설정 (aiomysql 대응)
        @event.listens_for(engine.sync_engine, "connect")
        def set_timezone(dbapi_connection, connection_record):
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute(f"SET time_zone = '{config.timezone or '+00:00'}'")
                cursor.close()
            except Exception as e:
                logger.warning(f"[DB] Failed to set time_zone: {e}")

        _ENGINE_CACHE[dsn] = engine

    return _ENGINE_CACHE[dsn]


def get_sessionmaker(service: Optional[str] = None) -> sessionmaker:
    """
    서비스명별 AsyncSession용 sessionmaker를 생성/캐시하여 반환합니다.
    """
    dsn = _service_dsn(service)
    if dsn not in _SESSIONMAKER_CACHE:
        engine = get_engine(service)
        _SESSIONMAKER_CACHE[dsn] = sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _SESSIONMAKER_CACHE[dsn]


# ── 기본(SessionMiddleware 등에서 사용할 기본 세션메이커) ─────────────────────
async_session_maker = get_sessionmaker()


# ── FastAPI Depends용 ────────────────────────────────────────────────────────
async def get_db(database_name: Optional[str] = None):
    """
    범용 비동기 DB 세션 의존성.
    - database_name: 지정 시 해당 서비스로 연결, 미지정 시 기본 서비스(config.database_service).
    """
    SessionLocal = get_sessionmaker(database_name)
    async with SessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"[DB] Session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()
