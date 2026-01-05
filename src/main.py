# src/main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from starlette.exceptions import HTTPException as StarletteHTTPException

import os
import time
# Load Env
from src.config import get_settings
config = get_settings()

from src.database import async_session_maker
from src.admin.router import admin_router
from src.app.router import app_router
from src.auth.router import auth_router
from src.user.router import user_router
from src.cache_utils import get_static_files_class
from src.middleware import CombinedMiddleware
from src.exceptions import (
    NotAuthenticatedException,
    not_authenticated_exception_handler,
    not_found_page_handler,
)


os.environ["TZ"] = config.timezone
try:
    time.tzset()  # 리눅스/유닉스 환경에서만 필요 (윈도우는 자동 적용)
except AttributeError:
    pass

# Determine the environment
environment = os.getenv("ENVIRONMENT", "loc")

# Initiate app with conditional documentation
if environment in ["loc"]:
    app = FastAPI(
        title=config.app_name,
        root_path="",
    )
elif environment in ["dev"]:
    app = FastAPI(
        title=config.app_name,
        root_path="/" + config.app_name,
    )
else:
    app = FastAPI(
        title=config.app_name,
        root_path="/" + config.app_name,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ---------------------------
# Root Page
# ---------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root(request: Request):
    """
    로그인 여부에 따라 다른 렌더링:
    - 로그인됨: main.html (OOB nav 포함)
    - 비로그인: /user/signin 으로 리다이렉트
    """

    user = getattr(request.state, "user", None)
    if not user:
        # 🚫 로그인되지 않았으면 로그인 페이지로 리다이렉트
        return RedirectResponse(url=request.url_for("signin_get"))

    # ✅ 로그인되어 있으면 메인 페이지 렌더링
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "main.html",
            "user": user,
        },
    )



@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


# ---------------------------
# Static Files
# ---------------------------
StaticFilesClass = get_static_files_class(environment)
app.mount("/static", StaticFilesClass(directory="./static"), name="static")


# ---------------------------
# Routers
# ---------------------------
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(app_router, prefix="/app", tags=["app"])
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(user_router, prefix="/user", tags=["user"])


# ---------------------------
# Middleware
# ---------------------------
# CombinedMiddleware 등록 (요청 기록 + 메뉴 생성)
app.add_middleware(
    CombinedMiddleware,
    db_session=async_session_maker,
)


# ---------------------------
# Exception Handlers
# ---------------------------
app.add_exception_handler(NotAuthenticatedException, not_authenticated_exception_handler)
app.add_exception_handler(StarletteHTTPException, not_found_page_handler)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=80,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
