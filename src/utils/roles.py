from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload
from src.user.models import User, Role


# ==========================================================
# ✅ 역할 검증 유틸리티
# ==========================================================
async def has_role(request: Request, db: AsyncSession, required_roles: list[str]) -> bool:
    """
    ✅ 사용자에게 required_roles 중 하나라도 있으면 True 반환
    - JSON 요청(fetch/axios)은 JSON 형태로 에러 응답
    - 일반 HTML 요청은 Redirect 또는 HTML 에러 처리
    """
    user = getattr(request.state, "user", None)
    is_json = _is_json_request(request)

    # ✅ 로그인 확인
    if not user:
        if is_json:
            raise_json(401, "Unauthorized")
        else:
            # 로그인 페이지로 리다이렉트
            return RedirectResponse(url=request.url_for("signin_get"), status_code=303)

    # ✅ 최신 사용자 정보 로드
    result = await db.execute(
        select(User)
        .options(joinedload(User.roles))
        .where(User.id == user.id)
    )
    db_user = result.scalars().first()

    if not db_user:
        if is_json:
            raise_json(404, "User not found")
        else:
            raise_html(404, "User not found")

    # ✅ 권한 검사
    user_roles = [r.name for r in db_user.roles]
    if any(role in user_roles for role in required_roles):
        return True

    # ✅ 권한 부족
    if is_json:
        raise_json(403, "Forbidden")
    else:
        raise_html(403, "권한이 없습니다.")


# ==========================================================
# ✅ 헬퍼 함수
# ==========================================================
def _is_json_request(request: Request) -> bool:
    """
    요청이 fetch/axios 등 JSON 요청인지 판별
    """
    accept = request.headers.get("accept", "").lower()
    xreq = request.headers.get("x-requested-with", "").lower()
    content_type = request.headers.get("content-type", "").lower()

    return (
        "application/json" in accept
        or "json" in content_type
        or xreq == "xmlhttprequest"
    )


def raise_json(status_code: int, detail: str):
    """
    JSON 형태의 에러 응답
    """
    raise HTTPException(
        status_code=status_code,
        detail={"error": True, "message": detail},
    )


def raise_html(status_code: int, message: str):
    """
    HTML 요청용 예외 (템플릿용 에러 페이지 렌더링)
    """
    raise HTTPException(
        status_code=status_code,
        detail=message,
    )
