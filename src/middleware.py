# src/middleware.py
from typing import List, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.future import select

from src.utils.history import record_user_history
from src.utils.security import get_current_user_from_cookie
from src.user.models import Menu, Role, user_role
from src.config import get_settings

config = get_settings()
ALGORITHM = "HS256"


class CombinedMiddleware(BaseHTTPMiddleware):
    """
    ✅ 통합 미들웨어
    - 로그인 자동 갱신 (RT 기반 AT 재발급)
    - 메뉴 자동 로드 (GET 요청 시)
    - 요청 히스토리 기록
    """

    def __init__(
        self,
        app,
        *,
        db_session,
        exempt_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.db_session = db_session
        self.exempt_paths = exempt_paths or [
            "/docs",
            "/openapi.json",
            "/redoc",
            "/health",
            "/static/",
            "/.well-known/",
        ]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        method = request.method.upper()

        # ✅ static, docs, health 등 제외
        if any(path.startswith(ex) for ex in self.exempt_paths):
            return await call_next(request)
        
        # ✅ Body 복사 (로그 기록용)
        try:
            request.state.body_raw = await request.body()
        except Exception:
            request.state.body_raw = b""

        async with self.db_session() as db:
            # 1️⃣ 로그인 사용자 확인
            user = await get_current_user_from_cookie(request, db)
            request.state.user = user

            # 2️⃣ 메뉴 트리 구성 (GET 요청만)
            if method == "GET":
                try:
                    result = await db.execute(
                        select(Menu).where(Menu.is_active == True).order_by(Menu.order)
                    )
                    menus = result.scalars().all()

                    user_roles = []
                    if user:
                        result = await db.execute(
                            select(Role)
                            .join(user_role, Role.uid == user_role.c.role_uid)
                            .where(user_role.c.user_uid == user.uid)
                        )
                        roles = result.scalars().all()
                        user_roles = [r.name.lower() for r in roles if r.name]

                    def menu_visible(menu: Menu) -> bool:
                        if not menu.visible_roles or menu.visible_roles.strip() == "":
                            return True
                        allowed_roles = [
                            r.strip().lower() for r in menu.visible_roles.split(",")
                        ]
                        return any(role in allowed_roles for role in user_roles)

                    def build_tree(parent_uid=None, parent_visible=True):
                        result = []
                        for m in menus:
                            if m.parent_uid == parent_uid:
                                if not parent_visible:
                                    continue
                                self_visible = menu_visible(m)
                                children = build_tree(m.uid, parent_visible=self_visible)
                                if self_visible:
                                    result.append(
                                        {
                                            "uid": m.uid,
                                            "name": m.name,
                                            "url": m.url,
                                            "icon": m.icon,
                                            "children": children,
                                        }
                                    )
                        return result

                    request.state.menus = build_tree()
                    request.state.current_path = path
                except Exception as e:
                    print(f"[MenuMiddleware] 메뉴 빌드 중 오류: {e}")
                    request.state.menus = []
                    request.state.current_path = path

        # 4️⃣ call_next() 후 response 쿠키 갱신 (response가 생긴 뒤에만 가능)
        response = await call_next(request)

        # 🔁 get_current_user_from_cookie() 내에서 새 토큰이 발급된 경우 쿠키 반영
        cookie_response = getattr(request.state, "_cookie_refresh_response", None)
        if cookie_response:
            print("\n[Middleware] 🔁 Detected new token cookies in _cookie_refresh_response")
            for header, value in cookie_response.raw_headers:
                # Set-Cookie 헤더를 현재 response에 복사
                if header.decode("latin1").lower() == "set-cookie":
                    print(f"[Middleware]   ➕ Set-Cookie -> {value.decode('latin1')}")
                    response.raw_headers.append((header, value))
            print("[Middleware] ✅ Cookie headers merged into response\n")
            

        # 3️⃣ 히스토리 기록
        try:
            await record_user_history(
                db,
                request,
                response,
                user=user,
                capture_body=True,
            )
        except Exception as e:
            print(f"[HistoryMiddleware] 기록 실패: {e}")
        
        return response
