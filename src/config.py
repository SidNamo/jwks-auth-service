# src/config.py
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
from typing import ClassVar, Optional


class Settings(BaseSettings):
    # ── App ─────────────────────────────────────────────────────────────────────
    app_name: str
    environment: str
    logging_level: str
    timezone: str = "UTC"
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    client_id: str
    client_secret: str

    # ── Default(Main) DB ────────────────────────────────────────────────────────
    db_main_host: str
    db_main_port: int
    db_main_user: str
    db_main_password: str
    db_main_name: str

    # 멀티 DB 기본 서비스명 (예: "main", "replica", "audit" 등)
    database_service: str = "main"

    # ENV 파일 경로(.env.dev / .env.prod 등)
    env_file_path: ClassVar[str] = os.path.join(
        ".", f".env.{os.getenv('ENVIRONMENT', 'loc')}"
    )
    model_config = SettingsConfigDict(
        env_file=env_file_path, env_file_encoding="utf-8"
    )

    # ── 하위 호환: 단일 DSN이 필요할 때 사용 ─────────────────────────────────────
    @property
    def database_url(self) -> str:
        """
        기본(main) DB의 동기 DSN(mysql+pymysql)을 반환합니다.
        """
        return (
            f"mysql+pymysql://{self.db_main_user}:{self.db_main_password}"
            f"@{self.db_main_host}:{self.db_main_port}/{self.db_main_name}"
        )

    # ── 멀티 DB 지원: 서비스명으로 DSN 가져오기 ─────────────────────────────────
    def get_database_url(self, service: Optional[str] = None) -> str:
        """
        서비스명(예: 'main', 'replica', 'audit')으로 DSN(mysql+pymysql)을 생성합니다.

        규칙:
        - service='main' → db_main_* 변수를 사용
        - service!='main' → 대문자 서비스 키로 환경변수 조회:
            DB_{SERVICE}_HOST, DB_{SERVICE}_PORT, DB_{SERVICE}_USER,
            DB_{SERVICE}_PASSWORD, DB_{SERVICE}_NAME
          (예: service='replica' → DB_REPLICA_HOST 등)
        """
        service = (service or self.database_service).strip()
        if service == "main":
            host = self.db_main_host
            port = self.db_main_port
            user = self.db_main_user
            pw = self.db_main_password
            name = self.db_main_name
        else:
            key = service.upper()
            def _get(name: str, required: bool = True, cast=int):
                env_key = f"DB_{key}_{name}"
                val = os.getenv(env_key, None)
                if val is None and required:
                    raise ValueError(
                        f"Missing environment variable: {env_key} "
                        f"(for database service '{service}')"
                    )
                if name == "PORT" and val is not None:
                    try:
                        return int(val)
                    except ValueError:
                        raise ValueError(f"{env_key} must be an integer")
                return val

            host = _get("HOST")
            port = _get("PORT")
            user = _get("USER", cast=str)
            pw = _get("PASSWORD", cast=str)
            name = _get("NAME", cast=str)

        return f"mysql+pymysql://{user}:{pw}@{host}:{port}/{name}"
    
@lru_cache
def get_settings():
    return Settings()
