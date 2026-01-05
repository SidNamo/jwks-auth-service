# src/user/models.py
from sqlalchemy import (
    Column, Integer, String, Enum, DateTime, func, ForeignKey, Text, Table, Boolean, JSON
)
from sqlalchemy.orm import relationship
from src.database import Base
import enum


class UserStatus(enum.Enum):
    USE = "USE"   # 활성화
    DEL = "DEL"   # 삭제
    WAIT = "WAIT" # 대기


# Many-to-Many 관계 매핑용 연결 테이블
user_role = Table(
    "user_role",
    Base.metadata,
    Column("user_uid", Integer, ForeignKey("user.uid", ondelete="CASCADE"), primary_key=True),
    Column("role_uid", Integer, ForeignKey("role.uid", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "user"

    uid = Column(Integer, primary_key=True, autoincrement=True, index=True)
    id = Column(String(255), nullable=False, index=True)
    pw = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    status = Column(Enum(UserStatus), nullable=False, default=UserStatus.WAIT)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # 관계
    roles = relationship("Role", secondary=user_role, back_populates="users")
    histories = relationship("UserHistory", back_populates="user")


class Role(Base):
    __tablename__ = "role"

    uid = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False)   # 권한 코드 (예: "ADMIN", "API_ACCESS")
    description = Column(String(255))                        # 설명

    # 관계
    users = relationship("User", secondary=user_role, back_populates="roles")



class UserHistory(Base):
    __tablename__ = "user_history"

    uid = Column(Integer, primary_key=True, autoincrement=True)

    # 기본 정보
    user_uid = Column(Integer, ForeignKey("user.uid"), nullable=True)
    ip_address = Column(String(45), nullable=False)     # IPv6까지
    url = Column(String(255), nullable=True)
    memo = Column(String(50), nullable=False)         # login, visit, api_call 등

    # ✅ 요청(request) 정보
    req_method = Column(String(10), nullable=True)      # GET / POST / PUT / DELETE
    req_header = Column(JSON, nullable=True)
    req_body = Column(JSON, nullable=True)
    req_query = Column(JSON, nullable=True)

    # ✅ 응답(response) 정보
    res_status = Column(Integer, nullable=True)
    res_header = Column(JSON, nullable=True)
    res_body = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # 관계
    user = relationship("User", back_populates="histories")


# ----------------------------------------
# Menu
# ----------------------------------------
class Menu(Base):
    """
    계층형 메뉴
    visible_roles: "admin,user" 형태 문자열로 접근 제어
    """
    __tablename__ = "menus"

    uid = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    icon = Column(String(50), nullable=True)  # 예: "home", "settings", "book"
    url = Column(String(255), nullable=True)
    parent_uid = Column(Integer, ForeignKey("menus.uid"), nullable=True)
    order = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, default=True)
    visible_roles = Column(Text, nullable=True)  # 예: "admin,user"

    parent = relationship("Menu", remote_side=[uid], back_populates="children")
    children = relationship("Menu", back_populates="parent", cascade="all, delete")

    def __repr__(self):
        return f"<Menu(name={self.name}, uid={self.uid}, parent_uid={self.parent_uid})>"