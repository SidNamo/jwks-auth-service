# src/admin/router.py
from __future__ import annotations
import json

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from sqlalchemy import text, select, delete

from src.config import get_settings
from src.database import get_db
from src.user.models import User, UserStatus, Role
from src.user.schemas import UserRequest
from src.app.models import Application, ApplicationCollaborator, ApplicationKey
from src.app.schemas import AppRequest
from src.utils.roles import has_role
from src.utils.paging import Paging
from src.utils.security import hash_password, generate_client_id, generate_hashed_key, generate_rsa_keypair, generate_kid
from src.utils.common import validate_ip, is_blank, is_only_whitespace, is_datetime_string, to_datetime

# -----------------------------------------------------
# 📦 초기 설정
# -----------------------------------------------------
admin_router = APIRouter(tags=["admin"])
templates = Jinja2Templates(directory="templates")
config = get_settings()


@admin_router.get("/users", response_class=HTMLResponse)
async def users_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
    paging: Paging = Depends(Paging.dep),  # ✅ 이렇게 한 줄로 사용
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_USER"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    # -------------------------------
    # 🔍 검색 조건 구성
    # -------------------------------
    base_sql = "FROM user WHERE 1=1"
    params = {}

    if query := paging.search.get("query"):
        base_sql += " AND ("
        base_sql += "     CAST(uid AS CHAR) LIKE :query"
        base_sql += "     OR id LIKE :query"
        base_sql += "     OR name LIKE :query"
        base_sql += ")"
        params["query"] = f"%{query}%"

    if uid := paging.search.get("uid"):
        base_sql += " AND CAST(uid AS CHAR) LIKE :uid"
        params["uid"] = f"%{uid}%"

    if name := paging.search.get("name"):
        base_sql += " AND name LIKE :name"
        params["name"] = f"%{name}%"

    if user_id := paging.search.get("id"):
        base_sql += " AND id LIKE :id"
        params["id"] = f"%{user_id}%"

    if status := paging.search.get("status"):
        base_sql += " AND status = :status"
        params["status"] = status

    created_start = paging.search.get("created_dt_start")
    created_end = paging.search.get("created_dt_end")
    if created_start and created_end:
        base_sql += " AND DATE(created_at) BETWEEN :start AND :end"
        params.update({"start": created_start, "end": created_end})
    elif created_start:
        base_sql += " AND DATE(created_at) >= :start"
        params["start"] = created_start
    elif created_end:
        base_sql += " AND DATE(created_at) <= :end"
        params["end"] = created_end

    # -----------------------------------------
    # 📊 총 개수 조회
    # -----------------------------------------
    count_sql = text(f"SELECT COUNT(*) {base_sql}")
    paging.list_total = (await db.execute(count_sql, params)).scalar() or 0

    # -----------------------------------------
    # 📋 실제 데이터 조회 (LIMIT / OFFSET)
    # -----------------------------------------
    offset = (paging.page - 1) * paging.list_size
    data_sql = text(f"""
        SELECT uid, id, name, status, created_at, updated_at
        {base_sql}
        ORDER BY uid DESC  -- ✅ UID 순으로 정렬 (생성순)
        LIMIT :limit OFFSET :offset
    """)
    params.update({"limit": paging.list_size, "offset": offset})

    result = await db.execute(data_sql, params)
    paging.content = result.mappings().all()

    
    roles = (await db.execute(select(Role))).scalars().all()  # ✅ 모든 권한 불러오기

    # -----------------------------------------
    # 🧾 템플릿 렌더링
    # -----------------------------------------
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "admin/users.html",
            "page": paging,
            "roles": roles, 
        },
    )

@admin_router.post("/users")
async def user_create(
    request: Request,
    payload: UserRequest,
    db: AsyncSession = Depends(get_db),
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_USER"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    # ✅ 유효성 검사
    if not payload.id or not payload.password or not payload.name:
        return JSONResponse({"detail": "아이디, 이름, 비밀번호는 필수 입력입니다."}, status_code=400)

    # ✅ ID 중복 검사
    existing = await db.execute(select(User).where(User.id == payload.id, User.status != UserStatus.DEL))
    if existing.scalars().first():
        return JSONResponse(
            {"detail": f"이미 활성 상태(ID={payload.id})의 사용자가 존재합니다."},
            status_code=400,
        )

    # ✅ 사용자 생성
    hashed_pw = hash_password(payload.password)
    new_user = User(
        id=payload.id,
        name=payload.name,
        pw=hashed_pw,
        status=UserStatus(payload.status or "WAIT"),
    )

    # ✅ 권한 설정 (uid 기반)
    if payload.roles:
        result = await db.execute(select(Role).where(Role.uid.in_(payload.roles)))
        new_user.roles = result.scalars().all()

    try:
        db.add(new_user)
        await db.commit()
        return JSONResponse({"message": "✅ 사용자 등록 완료"})
    except IntegrityError:
        await db.rollback()
        return JSONResponse({"detail": "DB 오류로 사용자 등록 실패"}, status_code=500)

@admin_router.get("/users/{uid}")
async def user_get(
    request: Request,
    uid: int,
    db: AsyncSession = Depends(get_db),
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_USER"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    # ✅ roles 미리 로드
    result = await db.execute(
        select(User)
        .options(selectinload(User.roles))
        .where(User.uid == uid)
    )
    edit_user = result.scalars().first()
    if not edit_user:
        raise HTTPException(status_code=404, detail="User not found")

    # ✅ name → uid 기반으로 변경
    return {
        "uid": edit_user.uid,
        "id": edit_user.id,
        "name": edit_user.name,
        "status": edit_user.status.value if hasattr(edit_user.status, "value") else str(edit_user.status),
        "roles": [r.uid for r in edit_user.roles],  # ✅ 권한 uid 목록
    }


@admin_router.patch("/users/{uid}")
async def user_update(
    request: Request,
    uid: int,
    payload: UserRequest,
    db: AsyncSession = Depends(get_db),
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_USER"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    result = await db.execute(
        select(User)
        .options(selectinload(User.roles))
        .where(User.uid == uid)
    )
    edit_user = result.scalars().first()
    if not edit_user:
        return JSONResponse({"detail": "사용자 정보를 불러오지 못했습니다."}, status_code=400)

    update_data = payload.dict(exclude_unset=True, exclude_none=True)
    new_status = update_data.get("status", edit_user.status)
    new_id = update_data.get("id", edit_user.id)

    # ✅ 중복 ID 검사
    stmt = select(User).where(
        User.id == new_id,
        User.status != UserStatus.DEL,
        User.uid != edit_user.uid,
    )
    result = await db.execute(stmt)
    duplicate_user = result.scalars().first()
    if duplicate_user and new_status != UserStatus.DEL:
        return JSONResponse(
            {"detail": f"이미 활성 상태(ID={new_id})의 사용자가 존재합니다."},
            status_code=400,
        )

    # ✅ 비밀번호 해시
    if "password" in update_data and update_data["password"]:
        update_data["pw"] = hash_password(update_data["password"])
        del update_data["password"]

    # ✅ 일반 필드
    for key, value in update_data.items():
        if key not in ["roles"] and hasattr(edit_user, key) and value not in (None, ""):
            setattr(edit_user, key, value)

    # ✅ 권한(Role) 수정 — uid 기준
    if "roles" in update_data:
        result = await db.execute(select(Role).where(Role.uid.in_(update_data["roles"])))
        new_roles = result.scalars().all()
        edit_user.roles = new_roles

    await db.commit()
    await db.refresh(edit_user)

    return {"result": "success"}







@admin_router.get("/apps", response_class=HTMLResponse)
async def apps_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
    paging: Paging = Depends(Paging.dep),
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    # -------------------------------
    # 🔍 검색 조건 구성
    # -------------------------------
    base_sql = """
        FROM application a
        LEFT JOIN application_collaborator ac ON a.uid = ac.application_uid
        LEFT JOIN user u ON ac.user_uid = u.uid
        WHERE 1=1
    """
    params = {}

    # ✅ 통합 검색
    if query := paging.search.get("query"):
        base_sql += """
            AND (
                CAST(a.uid AS CHAR) LIKE :query
                OR a.name LIKE :query
                OR a.client_id LIKE :query
                OR CAST(u.uid AS CHAR) LIKE :query
                OR u.id LIKE :query
                OR u.name LIKE :query
            )
        """
        params["query"] = f"%{query}%"

    # ✅ 기본 검색 조건들
    if uid := paging.search.get("uid"):
        base_sql += " AND CAST(a.uid AS CHAR) LIKE :uid"
        params["uid"] = f"%{uid}%"

    if name := paging.search.get("name"):
        base_sql += " AND a.name LIKE :name"
        params["name"] = f"%{name}%"

    if client_id := paging.search.get("client_id"):
        base_sql += " AND a.client_id LIKE :client_id"
        params["client_id"] = f"%{client_id}%"

    # ✅ 소유자 (uid, id, name 통합)
    if owner := paging.search.get("owner"):
        base_sql += """
            AND (
                CAST(u.uid AS CHAR) LIKE :owner
                OR u.id LIKE :owner
                OR u.name LIKE :owner
            )
        """
        params["owner"] = f"%{owner}%"

    # ✅ 등록일 기간
    created_start = paging.search.get("created_dt_start")
    created_end = paging.search.get("created_dt_end")
    if created_start and created_end:
        base_sql += " AND DATE(a.created_at) BETWEEN :start AND :end"
        params.update({"start": created_start, "end": created_end})
    elif created_start:
        base_sql += " AND DATE(a.created_at) >= :start"
        params["start"] = created_start
    elif created_end:
        base_sql += " AND DATE(a.created_at) <= :end"
        params["end"] = created_end

    # -----------------------------------------
    # 📊 총 개수 조회
    # -----------------------------------------
    count_sql = text(f"SELECT COUNT(DISTINCT a.uid) {base_sql}")
    paging.list_total = (await db.execute(count_sql, params)).scalar() or 0

    # -----------------------------------------
    # 📋 실제 데이터 조회 (LIMIT / OFFSET)
    # -----------------------------------------
    offset = (paging.page - 1) * paging.list_size
    data_sql = text(f"""
        SELECT 
            a.uid,
            a.name,
            a.client_id,
            a.created_at,
            a.updated_at,
            GROUP_CONCAT(DISTINCT u.name ORDER BY u.uid SEPARATOR ', ') AS admins
        {base_sql}
        GROUP BY a.uid
        ORDER BY a.uid DESC
        LIMIT :limit OFFSET :offset
    """)
    params.update({"limit": paging.list_size, "offset": offset})

    result = await db.execute(data_sql, params)
    paging.content = result.mappings().all()

    # -----------------------------------------
    # 🧾 템플릿 렌더링
    # -----------------------------------------
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "content_page": "admin/apps.html",
            "page": paging,
        },
    )

@admin_router.post("/apps")
async def app_post(
    request: Request,
    payload: AppRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    ✅ 어플리케이션 신규 생성
    """
    # ✅ 1. 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp

    # ✅ 2. 기본 입력값 검증 -------------------------
    # (1) 공백 문자열 및 null 검증
    for field_name, value in payload.dict(exclude_unset=True).items():
        if is_only_whitespace(value):
            raise HTTPException(status_code=400, detail=f"{field_name}에 공백만 입력할 수 없습니다.")
        if is_blank(value):
            raise HTTPException(status_code=400, detail=f"{field_name}이 비어 있습니다.")

    # (2) Client ID 중복 검사
    if payload.client_id:
        result = await db.execute(
            select(Application).where(Application.client_id == payload.client_id)
        )
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="이미 존재하는 Client ID입니다.")

    # (3) RSA 키 유효성 검사
    if payload.keys:
        for k in payload.keys:
            for field in ("created_at", "expired_at"):
                v = k.get(field)
                if v in (None, "", "null"):
                    continue
                if not is_datetime_string(str(v)):
                    raise HTTPException(status_code=400, detail=f"{field} 값이 잘못된 형식입니다: {v}")

        # ✅ 만료되지 않은 키 2개 이상 불가
        active_keys = [k for k in payload.keys if not k.get("expired_at")]
        if len(active_keys) > 1:
            raise HTTPException(
                status_code=400,
                detail="만료되지 않은 RSA 키(expired_at=None)는 1개만 존재해야 합니다."
            )

    # (4) 허용 IP 형식 검증
    if payload.allowed_ips:
        for ip in payload.allowed_ips:
            if not validate_ip(ip):
                raise HTTPException(status_code=400, detail=f"잘못된 IP 형식입니다: {ip}")

    # ✅ 3. 신규 등록 -------------------------
    try:
        new_app = Application(
            name=payload.name,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            allowed_ips=[ip.strip() for ip in (payload.allowed_ips or []) if ip.strip()],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(new_app)
        await db.flush()  # UID 확보용 (commit 전에 필요)

        # ✅ 4. 소유자 등록
        if payload.owners:
            for user_uid in payload.owners:
                db.add(ApplicationCollaborator(application_uid=new_app.uid, user_uid=user_uid))

        # ✅ 5. RSA 키 등록
        if payload.keys:
            for k in payload.keys:
                db.add(ApplicationKey(
                    application_uid=new_app.uid,
                    kid=k.get("kid"),
                    alg=k.get("alg", "RS256"),
                    use=k.get("use", "sig"),
                    public_key=k.get("public_key"),
                    private_key=k.get("private_key"),
                    created_at=to_datetime(k.get("created_at")),
                    expired_at=to_datetime(k.get("expired_at")),
                ))

        await db.commit()
        await db.refresh(new_app)

        return {
            "message": "✅ 어플리케이션이 성공적으로 생성되었습니다.",
            "uid": new_app.uid,
        }

    except HTTPException:
        await db.rollback()
        raise

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"서버 오류: {str(e)}")

@admin_router.get("/apps/search_user")
async def app_user_get(
    request: Request, 
    keyword: str = Query(..., description="검색 키워드"),
    db: AsyncSession = Depends(get_db)
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    keyword = keyword.strip()

    q = await db.execute(
        text("""
        SELECT uid, id, name
        FROM user
        WHERE (CAST(uid AS CHAR) LIKE :kw OR id LIKE :kw OR name LIKE :kw)
          AND status != 'DEL'
        ORDER BY uid DESC
        LIMIT 10
        """),
        {"kw": f"%{keyword}%"},
    )

    result = q.mappings().all()
    result_dicts = [dict(r) for r in result]   # ✅ RowMapping → dict

    return JSONResponse({
        "data": result_dicts,
        "count": len(result_dicts)
    })


@admin_router.get("/apps/generate")
async def app_generate(
    request: Request,
    type: str = Query(..., description="생성할 키 타입 (CLIENT_ID, CLIENT_SECRET, RSA)"),
    db: AsyncSession = Depends(get_db),
):
    # 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp

    key_type = type.upper()

    if key_type == "CLIENT_ID":
        while True:
            new_id = generate_client_id()
            result = await db.execute(select(Application).where(Application.client_id == new_id))
            if not result.scalar_one_or_none():
                break
        return {"message": "✅ Client ID 생성 완료", "client_id": new_id}

    elif key_type == "CLIENT_SECRET":
        new_secret = generate_hashed_key()
        return {"message": "✅ Client Secret 생성 완료", "client_secret": new_secret}

    elif key_type == "RSA":
        private_key, public_key = generate_rsa_keypair()
        now = datetime.now(timezone.utc)
        new_key = {
            "kid": generate_kid(),
            "alg": "RS256",
            "use": "sig",
            "public_key": public_key,
            "private_key": private_key,
            # ✅ 포맷 통일: 초 단위, 타임존 없음 (검증 함수와 호환)
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expired_at": None,
        }
        return {"message": "✅ RSA 키 생성 완료", "key": new_key}

    else:
        raise HTTPException(status_code=400, detail="잘못된 type 값입니다.")
    

@admin_router.get("/apps/{uid}")
async def app_get(
    request: Request,
    uid: int,
    db: AsyncSession = Depends(get_db),
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    q = await db.execute(
        select(Application, User, ApplicationKey)
        .join(ApplicationCollaborator, ApplicationCollaborator.application_uid == Application.uid, isouter=True)
        .join(User, User.uid == ApplicationCollaborator.user_uid, isouter=True)
        .join(ApplicationKey, ApplicationKey.application_uid == Application.uid, isouter=True)
        .where(Application.uid == uid)
    )
    rows = q.all()

    if not rows:
        app = await db.get(Application, uid)
        if not app:
            raise HTTPException(status_code=404, detail="앱을 찾을 수 없습니다.")
        return {
            "uid": app.uid,
            "name": app.name,
            "client_id": app.client_id,
            "client_secret": app.client_secret,
            "allowed_ips": app.allowed_ips or [],
            "owners": [],
            "keys": [],
        }

    app, user, key = rows[0][0], rows[0][1], rows[0][2]
    owners = [
        {"uid": u.uid, "id": u.id, "name": u.name}
        for (_, u, _) in rows if u
    ]
    keys = [
        {
            "kid": k.kid,
            "alg": k.alg,
            "use": k.use,
            "public_key": k.public_key,
            "private_key": k.private_key,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "expired_at": k.expired_at.isoformat() if k.expired_at else None,
        }
        for (_, _, k) in rows if k
    ]

    return {
        "uid": app.uid,
        "name": app.name,
        "client_id": app.client_id,
        "client_secret": app.client_secret,
        "allowed_ips": app.allowed_ips or [],
        "owners": owners,
        "keys": keys,
    }


@admin_router.patch("/apps/{uid}")
async def app_update(
    request: Request,
    uid: int,
    payload: AppRequest,
    db: AsyncSession = Depends(get_db),
):
    # ✅ 1. 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp

    # ✅ 2. 앱 존재 여부 확인
    app = await db.get(Application, uid)
    if not app:
        raise HTTPException(status_code=404, detail="앱을 찾을 수 없습니다.")

    # ✅ 3. 변경 데이터 검증 -------------------------
    # (1) 공백 문자열 및 null 검증
    for field_name, value in payload.dict(exclude_unset=True).items():
        if is_only_whitespace(value):
            raise HTTPException(status_code=400, detail=f"{field_name}에 공백만 입력할 수 없습니다.")
        if is_blank(value):
            raise HTTPException(status_code=400, detail=f"{field_name}이 비어 있습니다.")

    # (2) Client ID 중복 검사
    if payload.client_id:
        result = await db.execute(
            select(Application).where(
                Application.client_id == payload.client_id,
                Application.uid != uid
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="이미 존재하는 Client ID입니다.")

    # (3) RSA 키 유효성 검사
    if payload.keys:
        # ✅ created_at, expired_at 타입 검증
        for k in payload.keys:
            for field in ("created_at", "expired_at"):
                v = k.get(field)
                if v in (None, "", "null"):
                    continue  # None 허용
                if not is_datetime_string(str(v)):
                    raise HTTPException(status_code=400, detail=f"{field} 값이 잘못된 형식입니다: {v}")

        # ✅ 만료되지 않은 키 2개 이상 불가
        active_keys = [k for k in payload.keys if not k.get("expired_at")]
        if len(active_keys) > 1:
            raise HTTPException(
                status_code=400,
                detail="만료되지 않은 RSA 키(expired_at=None)는 1개만 존재해야 합니다."
            )

    # (4) 허용 IP 형식 검증
    if payload.allowed_ips:
        for ip in payload.allowed_ips:
            if not validate_ip(ip):
                raise HTTPException(status_code=400, detail=f"잘못된 IP 형식입니다: {ip}")

    # ✅ 4. 실제 변경 처리 -------------------------
    changed = False

    try:
        if payload.name is not None and payload.name != app.name:
            app.name = payload.name
            changed = True

        if payload.client_id is not None and payload.client_id != app.client_id:
            app.client_id = payload.client_id
            changed = True

        if payload.client_secret and payload.client_secret != app.client_secret:
            app.client_secret = payload.client_secret
            changed = True

        if payload.allowed_ips is not None:
            cleaned_ips = [ip.strip() for ip in payload.allowed_ips if isinstance(ip, str) and ip.strip()]
            if json.dumps(cleaned_ips) != json.dumps(app.allowed_ips):
                app.allowed_ips = cleaned_ips
                changed = True

        if payload.owners is not None:
            # 기존 owner 전체 삭제
            await db.execute(
                delete(ApplicationCollaborator).where(ApplicationCollaborator.application_uid == uid)
            )
            # 새 owner 추가
            for user_uid in payload.owners:
                db.add(ApplicationCollaborator(application_uid=uid, user_uid=user_uid))
            changed = True

        if payload.keys is not None:
            # 기존 키 전체 삭제
            await db.execute(
                delete(ApplicationKey).where(ApplicationKey.application_uid == uid)
            )

            # 새 키 추가 (문자열을 datetime으로 변환)
            for k in payload.keys:
                db.add(ApplicationKey(
                    application_uid=uid,
                    kid=k.get("kid"),
                    alg=k.get("alg", "RS256"),
                    use=k.get("use", "sig"),
                    public_key=k.get("public_key"),
                    private_key=k.get("private_key"),
                    created_at=to_datetime(k.get("created_at")),
                    expired_at=to_datetime(k.get("expired_at")),
                ))
            changed = True

        if not changed:
            raise HTTPException(status_code=400, detail="변경된 내용이 없습니다.")

        await db.commit()
        await db.refresh(app)
        return {"message": "✅ 앱 정보가 저장되었습니다."}

    except HTTPException:
        await db.rollback()
        raise

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"서버 오류: {str(e)}")



@admin_router.delete("/apps/{uid}")
async def app_delete(
    request: Request, 
    uid: int, 
    db: AsyncSession = Depends(get_db)
):
    # ✅ 권한 확인
    resp = await has_role(request, db, ["ADMIN", "ADMIN_APPLICATION"])
    if isinstance(resp, RedirectResponse):
        return resp  # ✅ RedirectResponse 반환 시 즉시 종료

    app = await db.get(Application, uid)
    if not app:
        raise HTTPException(status_code=404, detail="앱을 찾을 수 없습니다.")

    await db.delete(app)
    await db.commit()
    return {"message": "✅ 앱이 삭제되었습니다."}

