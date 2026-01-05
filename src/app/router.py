# src/app/router.py
from __future__ import annotations

# ────────────────────────────────
# 📦 FastAPI
# ────────────────────────────────
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# ────────────────────────────────
# 🧩 SQLAlchemy
# ────────────────────────────────
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

# ────────────────────────────────
# 🏗️ 내부 모듈
# ────────────────────────────────
from src.app.models import Application, ApplicationCollaborator
from src.config import get_settings
from src.database import get_db
from src.user.models import User
from src.utils.paging import Paging
from src.utils.roles import has_role


# -----------------------------------------------------
# 📦 초기 설정
# -----------------------------------------------------
app_router = APIRouter(tags=["app"])
templates = Jinja2Templates(directory="templates")
config = get_settings()



@app_router.get("/list", response_class=HTMLResponse)
async def list_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    📋 어플리케이션 목록 페이지
    """
    # ✅ 권한 확인
    resp = await has_role(request, db, ["USER"])
    if isinstance(resp, RedirectResponse):
        return resp  # 로그인 페이지로 이동 등

    # ✅ ORM 조회
    result = await db.execute(
        select(Application)
        .options(
            selectinload(Application.collaborators).selectinload(ApplicationCollaborator.user)
        )
        .order_by(Application.uid.desc())
    )
    apps = result.scalars().unique().all()

    # ✅ owners 문자열로 가공
    app_list = []
    for app in apps:
        owners = (
            ", ".join(
                [ac.user.name for ac in app.collaborators if ac.user]
            )
            if app.collaborators else "-"
        )
        app_list.append({
            "uid": app.uid,
            "name": app.name,
            "client_id": app.client_id,
            "created_at": app.created_at,
            "updated_at": app.updated_at,
            "owners": owners,
        })

    # ✅ 템플릿 렌더링
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "app/list.html",
            "apps": app_list,
        },
    )
