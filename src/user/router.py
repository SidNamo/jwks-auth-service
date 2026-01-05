# src/user/router.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Body
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from src.config import get_settings
from src.database import get_db
from src.user.models import Menu, User, UserStatus
from src.user.schemas import UserRequest
from src.utils.common import get_internal_base_url
from src.utils.roles import has_role
from src.utils.security import TokenCookieManager, hash_password, verify_password

# -----------------------------------------------------
# 📦 초기 설정
# -----------------------------------------------------
user_router = APIRouter(tags=["user"])
templates = Jinja2Templates(directory="templates")
config = get_settings()


# ---------------------------
# Sign in / out / up
# ---------------------------
@user_router.get("/signin", response_class=HTMLResponse)
async def signin_get(request: Request):
    user = getattr(request.state, "user", None)
    if user:
        # 🚫 로그인 되어 있으면 메인 페이지로 리다이렉트
        return RedirectResponse(url=request.url_for("root"))
    
    response = templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "user/signin.html",
        },
    )
    
    token_mgr = TokenCookieManager()
    token_mgr.clear_tokens(response)

    return response



@user_router.post("/signin")
async def signin_post(
    request: Request,
    payload: UserRequest,
    db: AsyncSession = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if user:
        # 🚫 로그인 되어 있으면 에러 
        return HTMLResponse("잘못된 요청입니다.", status_code=400)
    

    # ----------------------------------------------------------
    # ① 사용자 인증
    # ----------------------------------------------------------
    result = await db.execute(
        select(User).where(
            User.id == payload.id,
            User.status.in_([UserStatus.USE, UserStatus.WAIT]),
        )
    )
    user: User = result.scalars().first()

    if not user or not verify_password(payload.password, user.pw):
        return JSONResponse({"detail": "잘못된 아이디 또는 비밀번호입니다."}, status_code=400)

    if user.status != UserStatus.USE:
        return JSONResponse({"detail": "관리자 승인 대기 중입니다."}, status_code=403)

    # ----------------------------------------------------------
    # ② 토큰 요청 준비
    # ----------------------------------------------------------
    client_id = config.client_id
    client_secret = config.client_secret
    unique_key = str(user.uid)
    device = config.environment + "_" + (request.headers.get("X-Device") or request.headers.get("User-Agent") or "unknown")
    ip = request.client.host or ""

    # timestamp를 body 안에 포함
    timestamp = int(datetime.now(timezone.utc).timestamp())

    # ✅ body 구성
    body = {
        "unique_key": unique_key,
        "device": device,
        "ip": ip,
        "timestamp": timestamp,
    }

    # ✅ JSON 직렬화
    raw_body = json.dumps(body, ensure_ascii=False)

    # ----------------------------------------------------------
    # ③ HMAC 서명 생성
    # ----------------------------------------------------------
    # body → UTF-8 → message로 사용
    message = raw_body.encode("utf-8")

    signature = base64.b64encode(
        hmac.new(
            client_secret.encode("utf-8"),  # key
            message,                        # message
            hashlib.sha256                  # digest
        ).digest()
    ).decode()

    headers = {
        "Content-Type": "application/json",
        "X-Client-Id": client_id,
        "X-Signature": signature,
    }

    # ----------------------------------------------------------
    # ④ 내부 호출: /auth/token
    # ----------------------------------------------------------
    async with httpx.AsyncClient(base_url=get_internal_base_url(request, config)) as client:
        resp = await client.post("/auth/token", content=raw_body, headers=headers)

    if resp.status_code != 200:
        return HTMLResponse(f"토큰 발급 실패: {resp.text}", status_code=400)

    tokens = resp.json()
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    # ----------------------------------------------------------
    # ⑤ 쿠키에 토큰 저장
    # ----------------------------------------------------------
    response = JSONResponse({
        "message": "로그인 성공",
        "redirect": str(request.base_url)
    })

    token_mgr = TokenCookieManager()
    token_mgr.set_tokens(request, response, access_token, refresh_token, payload.remember_me)

    return response


@user_router.get("/signout", response_class=HTMLResponse)
async def signout_get(request: Request, db: AsyncSession = Depends(get_db)):
    """
    ✅ 로그아웃 처리 (전체 페이지 이동)
    - Access/Refresh Token을 단순히 전달하여 /auth/revoke 호출
    - JWT 검증 없이 key 배열만 body로 전송
    - 실패해도 쿠키는 무조건 삭제
    """
    client_id = config.client_id
    client_secret = config.client_secret
    base_url = str(request.base_url)

    token_mgr = TokenCookieManager()
    tokens = token_mgr.get_tokens(request)
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    # ✅ revoke 요청 body 구성 (key 배열만 포함)
    timestamp = int(datetime.now(timezone.utc).timestamp())
    revoke_body = {
        "token": [access_token, refresh_token],
        "timestamp": timestamp,
    }
    raw_body = json.dumps(revoke_body, ensure_ascii=False)

    # ✅ HMAC message = base64(body.encode("utf-8"))
    message = raw_body.encode("utf-8")

    signature = base64.b64encode(
        hmac.new(
            client_secret.encode("utf-8"),                  # key
            message,                        # message
            hashlib.sha256                  # digest
        ).digest()
    ).decode()

    headers = {
        "Content-Type": "application/json",
        "X-Client-Id": client_id,
        "X-Signature": signature,
    }

    # ✅ 내부 요청: /auth/revoke 호출
    async with httpx.AsyncClient(base_url=get_internal_base_url(request, config)) as client:
        try:
            await client.post("/auth/revoke", content=raw_body, headers=headers)
        except Exception:
            # 실패해도 쿠키는 무조건 제거
            pass

    # ✅ 쿠키 삭제 및 리다이렉트
    response = RedirectResponse(url=request.url_for("signin_get"))
    # response = RedirectResponse(url="/user/signin", status_code=302)
    token_mgr.clear_tokens(response)
    # ✅ refresh 쿠키 병합 방지 (_cookie_refresh_response 제거)
    if hasattr(request.state, "_cookie_refresh_response"):
        delattr(request.state, "_cookie_refresh_response")

    return response


@user_router.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request):
    """
    회원가입 페이지 렌더
    """
    user = getattr(request.state, "user", None)
    if user:
        # 🚫 로그인 되어 있으면 메인 페이지로 리다이렉트
        return RedirectResponse(url=request.url_for("root"))
    
    response =  templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "user/signup.html",
        },
    )

    token_mgr = TokenCookieManager()
    token_mgr.clear_tokens(response)

    return response


@user_router.post("/signup")
async def signup_post(
    request: Request,
    payload: UserRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    회원가입 처리
    """
    """
    ✅ 회원가입 처리 (Pydantic 스키마 사용)
    """
    user = getattr(request.state, "user", None)
    if user:
        return JSONResponse({"detail": "잘못된 요청입니다."}, status_code=400)

    # ----------------------------------------------------------
    # ① 중복 및 유효성 검사
    # ----------------------------------------------------------
    existing = await db.execute(
        select(User).where(
            User.id == payload.id,
            User.status.in_([UserStatus.USE, UserStatus.WAIT]),
        )
    )
    if existing.scalars().first():
        return JSONResponse({"detail": "이미 사용 중인 아이디입니다."}, status_code=400)

    if payload.password != payload.password_verify:
        return JSONResponse({"detail": "비밀번호가 동일하지 않습니다."}, status_code=400)

    # ----------------------------------------------------------
    # ② 사용자 생성
    # ----------------------------------------------------------
    hashed_pw = hash_password(payload.password)
    new_user = User(id=payload.id, name=payload.name, pw=hashed_pw, status=UserStatus.WAIT)
    db.add(new_user)
    await db.commit()

    return JSONResponse({"message": "회원가입이 완료되었습니다!\n관리자 승인 후 이용 가능합니다.", "redirect": str(request.base_url)})















# @user_router.get("/me", response_model=UserResponse)
# async def get_me(
#     request: Request,
#     db: AsyncSession = Depends(get_db),
# ):
#     me_uid = request.state.session_data.get("user_uid")
#     if not me_uid:
#         raise HTTPException(status_code=401, detail="Unauthorized")

#     me = await _get_user_by_uid(db, me_uid)
#     if not me:
#         raise HTTPException(status_code=404, detail="User not found")

#     return UserResponse(
#         uid=me.uid,
#         email=me.email,
#         name=me.name,
#         status=me.status.value if hasattr(me.status, "value") else str(me.status),
#     )


# @user_router.patch("/me", response_model=UserResponse)
# async def update_me(
#     request: Request,
#     update: UserUpdate,
#     db: AsyncSession = Depends(get_db),
# ):
#     me_uid = request.state.session_data.get("user_uid")
#     if not me_uid:
#         raise HTTPException(status_code=401, detail="Unauthorized")

#     db_user = await _get_user_by_uid(db, me_uid)
#     if not db_user:
#         raise HTTPException(status_code=404, detail="User not found")

#     if update.name is not None:
#         db_user.name = update.name
#     if update.pw is not None and update.pw != "":
#         db_user.pw = hash_password(update.pw)  # ✅ 해시
#     if update.status is not None:
#         try:
#             db_user.status = UserStatus(update.status)
#         except Exception:
#             pass

#     await db.commit()
#     await db.refresh(db_user)

#     await record_user_action(db, request, action="user_update_self", user_uid=db_user.uid)
#     return UserResponse(
#         uid=db_user.uid,
#         email=db_user.email,
#         name=db_user.name,
#         status=db_user.status.value if hasattr(db_user.status, "value") else str(db_user.status),
#     )


# @user_router.patch("/{user_uid}", response_model=UserResponse)
# async def update_user(
#     user_uid: int,
#     request: Request,
#     update: UserUpdate,
#     db: AsyncSession = Depends(get_db),
# ):
#     if not has_role(request, "ADMIN"):
#         await record_user_action(db, request, action="forbidden_update_other", user_uid=user_uid)
#         raise HTTPException(status_code=403, detail="Not allowed to update user")

#     db_user = await _get_user_by_uid(db, user_uid)
#     if not db_user:
#         await record_user_action(db, request, action="user_not_found_update_other", user_uid=user_uid)
#         raise HTTPException(status_code=404, detail="User not found")

#     if update.name is not None:
#         db_user.name = update.name
#     if update.pw is not None and update.pw != "":
#         db_user.pw = hash_password(update.pw)  # ✅ 해시
#     if update.status is not None:
#         try:
#             db_user.status = UserStatus(update.status)
#         except Exception:
#             pass

#     await db.commit()
#     await db.refresh(db_user)

#     await record_user_action(db, request, action="user_update_other", user_uid=db_user.uid)
#     return UserResponse(
#         uid=db_user.uid,
#         email=db_user.email,
#         name=db_user.name,
#         status=db_user.status.value if hasattr(db_user.status, "value") else str(db_user.status),
#     )


# @user_router.delete("/{user_uid}")
# async def delete_user(
#     user_uid: int,
#     request: Request,
#     db: AsyncSession = Depends(get_db),
# ):
#     me_uid = request.state.session_data.get("user_uid")
#     is_admin = has_role(request, "ADMIN")

#     if (not is_admin) and (me_uid != user_uid):
#         await record_user_action(db, request, action="forbidden_delete_other", user_uid=user_uid)
#         raise HTTPException(status_code=403, detail="Not allowed to delete user")

#     db_user = await _get_user_by_uid(db, user_uid)
#     if not db_user:
#         await record_user_action(db, request, action="user_not_found_delete_other", user_uid=user_uid)
#         raise HTTPException(status_code=404, detail="User not found")

#     db_user.status = UserStatus.DEL
#     await db.commit()

#     await record_user_action(db, request, action="user_delete_other", user_uid=user_uid)
#     return {"message": f"User {user_uid} deleted"}
