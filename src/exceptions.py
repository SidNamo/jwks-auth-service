# src/exceptions.py
from __future__ import annotations

from typing import Union

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exception_handlers import http_exception_handler

templates = Jinja2Templates(directory="templates")

# -------------------------
# Custom Exception Classes
# -------------------------
class NotAuthenticatedException(HTTPException):
    def __init__(self, detail: str = "로그인이 필요합니다."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)



# -------------------------
# Helper: 경로/헤더 기반 요청 성격 판별
# -------------------------
def _is_api_request(request: Request) -> bool:
    """
    - /api로 시작하면 API로 간주
    - 혹은 Accept 헤더에 application/json이 포함되면 API로 간주
    """
    path = request.url.path or ""
    if path.startswith("/api"):
        return True
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return True
    return False

def _is_docs_or_static(request: Request) -> bool:
    """
    문서/오픈API/정적 파일 등은 리다이렉트 대상에서 제외
    """
    path = request.url.path or ""
    return (
        path.startswith("/docs")
        or path.startswith("/openapi.json")
        or path.startswith("/redoc")
        or path.startswith("/health")
        or path.startswith("/static")
        or path == "/favicon.ico"
    )


# -------------------------
# Exception Handlers
# -------------------------

# ✅ 로그인 안 된 경우
async def not_authenticated_exception_handler(request: Request, exc):
    is_htmx = request.headers.get("hx-request") == "true"

    context = {
        "request": request,
        "status_code": getattr(exc, "status_code", 401),
        "message": getattr(exc, "detail", "로그인이 필요합니다."),
    }

    # ✅ API 요청이면 JSON으로 반환
    if _is_api_request(request):
        return JSONResponse(
            status_code=context["status_code"],
            content={"detail": context["message"]},
        )

    # ✅ HTMX 요청 → partial + nav OOB 포함
    if is_htmx:
        # 로그인 페이지 + nav 동시 갱신 (OOB)
        return templates.TemplateResponse(
            "user/signin.html",  # ← 이 파일이 nav 포함 OOB 버전이어야 합니다
            context,
            status_code=401,
        )

    # ✅ 일반 접근 시 base 전체 렌더
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request, 
            "nav": "nav.html", 
            "content_page": "user/signin.html",
        },
    )



# -------------------------
# Catch-all 404 처리
# - API: JSON 404
# - 웹 페이지(GET/HEAD): "/"로 307 리다이렉트
# - 그 외: 기본 핸들러
# -------------------------
async def not_found_page_handler(request: Request, exc: StarletteHTTPException):
    """
    ✅ 404 등 존재하지 않는 경로 접근 시 HTML 에러 페이지 렌더링
    """
    if exc.status_code not in (404, 405):
        return await http_exception_handler(request, exc)

    # API 요청은 JSON으로 응답
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept or request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not Found", "path": request.url.path},
        )

    # 일반 웹 접근은 템플릿 렌더
    context = {
        "request": request,
        "status_code": 404,
        "message": f"요청하신 페이지 ({request.url.path})를 찾을 수 없습니다.",
        "content_page": "error.html",
    }

    return templates.TemplateResponse("base.html", context, status_code=404)
