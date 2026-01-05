# src/auth/models.py
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, JSON,
    ForeignKey, UniqueConstraint, Index, func
)
from sqlalchemy.orm import relationship
from src.database import Base
from datetime import datetime


class Application(Base):
    __tablename__ = "application"

    uid = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)                       # 앱 이름
    client_id = Column(String(64), nullable=False, unique=True)       # 클라이언트 아이디
    client_secret = Column(String(255), nullable=False)              # 비밀키 해시
    allowed_ips = Column(JSON, nullable=True)                         # ✅ 허용 IP 목록 (JSON 배열)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # 관계
    collaborators = relationship("ApplicationCollaborator", back_populates="application", cascade="all, delete-orphan")
    tokens = relationship("Token", back_populates="application", cascade="all, delete-orphan")
    keys = relationship("ApplicationKey", back_populates="application", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_application_name", "name"),
    )


class ApplicationCollaborator(Base):
    """
    공동 작업자 (Application - User N:M)
    """
    __tablename__ = "application_collaborator"

    application_uid = Column(Integer, ForeignKey("application.uid", ondelete="CASCADE"), primary_key=True)
    user_uid = Column(Integer, ForeignKey("user.uid", ondelete="CASCADE"), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # 관계
    application = relationship("Application", back_populates="collaborators")
    user = relationship("User")  # user.models.User 와 연결


class ApplicationKey(Base):
    """
    🔐 클라이언트별 JWKS 키 버전 관리
    - rotate 시 새 레코드 추가
    - created_at 최신값이 활성 키
    - expired_at으로 만료 시점 관리
    """
    __tablename__ = "application_key"

    application_uid = Column(Integer, ForeignKey("application.uid", ondelete="CASCADE"), primary_key=True)
    kid = Column(String(128), primary_key=True)
    alg = Column(String(32), nullable=False, default="RS256")
    use = Column(String(16), nullable=False, default="sig")  # sig | enc
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expired_at = Column(DateTime(timezone=True), nullable=True)

    application = relationship("Application", back_populates="keys")

    __table_args__ = (
        Index("ix_appkey_app", "application_uid"),
        UniqueConstraint("application_uid", "kid", name="uq_appkey_app_kid"),
    )


class Token(Base):
    """
    🔑 토큰 저장 테이블 (Access / Refresh)
    - jti: 전역 고유 식별자 (Primary Key)
    - application_uid + unique_key + device + ip + typ: 유니크 제약
    - ip, device는 null 대신 빈 문자열("") 기본값 사용 (NULL은 UNIQUE 검사 회피)
    """

    __tablename__ = "token"

    jti = Column(String(128), primary_key=True)  # JWT ID, 전역 유니크

    application_uid = Column(Integer, ForeignKey("application.uid", ondelete="CASCADE"), nullable=False)
    typ = Column(String(16), nullable=False)              # access | refresh
    unique_key = Column(String(128), nullable=False)      # 외부 unique key

    # ✅ NULL 대신 빈 문자열 기본값 → 완전한 UNIQUE 보장
    ip = Column(String(45), nullable=False, server_default="")
    device = Column(Text, nullable=False, server_default="")

    token_hash = Column(String(255), nullable=False)
    scope = Column(Text, nullable=True)
    data = Column(JSON, nullable=True)
    options = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    expired_at = Column(DateTime(timezone=True), nullable=False)

    # 관계
    application = relationship("Application", back_populates="tokens")

    __table_args__ = (
        # ✅ 유니크 제약
        UniqueConstraint(
            "application_uid",
            "unique_key",
            "device",
            "ip",
            "typ",
            name="uq_token_app_key_device_ip_typ",
        ),
        # ✅ 인덱스들
        Index("ix_token_app", "application_uid"),
        Index("ix_token_expired_at", "expired_at"),
        Index("ix_token_unique_key", "unique_key"),
        Index("ix_token_ip", "ip"),
        Index("ix_token_device", "device"),
    )