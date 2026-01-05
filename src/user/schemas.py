from pydantic import BaseModel, Field, field_validator
from typing import Optional


# ✅ 회원 정보 요청 스키마 (optional 버전)
class UserRequest(BaseModel):
    uid: Optional[int] = Field(None, description="사용자 uid")
    id: Optional[str] = Field(None, description="사용자 아이디")
    name: Optional[str] = Field(None, description="이름")
    password: Optional[str] = Field(None, description="비밀번호")
    password_verify: Optional[str] = Field(None, description="비밀번호 확인")
    status: Optional[str] = Field(None, description="상태")
    roles: Optional[list[int]] = Field(None, description="권한 목록")
    remember_me: Optional[bool] = Field(default=False, description="자동 로그인 여부")

    # ✅ 문자열 형태의 true/false/on/off 도 안전하게 처리
    @field_validator("remember_me", mode="before")
    def normalize_bool(cls, v):
        if isinstance(v, str):
            return v.lower() in ["true", "1", "yes", "on"]
        return bool(v)