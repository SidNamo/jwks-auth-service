# src/auth/schemas.py
from pydantic import BaseModel, Field
from typing import Optional


class AppRequest(BaseModel):
    uid: Optional[int] = Field(None, description="앱 UID")
    name: Optional[str] = Field(None, description="앱 이름")
    client_id: Optional[str] = Field(None, description="클라이언트 아이디")
    client_secret: Optional[str] = Field(None, description="클라이언트 시크릿")
    allowed_ips: Optional[list[str]] = Field(None, description="허용 IP 목록 (JSON 배열)")
    owners: Optional[list[int]] = Field(default_factory=list, description="소유자 UID 목록")
    keys: Optional[list[dict]] = Field(default_factory=list, description="RSA 키 목록")
    created_at: Optional[str] = Field(None, description="등록일 (검색용)")
    created_dt_start: Optional[str] = Field(None, description="등록 시작일")
    created_dt_end: Optional[str] = Field(None, description="등록 종료일")
