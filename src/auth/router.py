# src/auth/router.py
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from jose import ExpiredSignatureError, JWTError, jwt
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.config import get_settings
from src.app.models import Application, ApplicationKey, Token
from src.database import get_db
from src.utils.security import (
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    generate_unique_jti,
    get_latest_app_key,
    hash_password,
    verify_hmac_and_get_app,
    verify_jwt_and_get_payload,
)

# -----------------------------------------------------
# 📦 Router & Constants
# -----------------------------------------------------
config = get_settings()
auth_router = APIRouter(tags=["auth"])


# -----------------------------------------------------
# 🧩 Helper functions
# -----------------------------------------------------
def _b64url_uint(i: int) -> str:
    """int -> base64url (without padding)"""
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


def _generate_kid() -> str:
    """KID = 날짜(YYYYMMDD) + UUID4"""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{today}-{uuid.uuid4()}"



# ---------------------------------------------------------
# 🪙 토큰 발급 (JWKS + HMAC)
# ---------------------------------------------------------
@auth_router.post("/token")
async def issue_tokens(request: Request, db: AsyncSession = Depends(get_db)):
    """
    ✅ 토큰 발급 (Access / Refresh)
    - HMAC 검증
    - unique_key + device + ip 기준으로 기존 토큰 삭제 후 재발급
    """
    # 1️⃣ 요청 본문 읽기
    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")

    # 2️⃣ HMAC 검증 (요청 body 포함)
    app = await verify_hmac_and_get_app(request, db, raw_body)

    # 3️⃣ JSON 파싱
    import json
    try:
        body = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    unique_key = body.get("unique_key")
    if not unique_key:
        raise HTTPException(status_code=400, detail="Missing unique_key")

    # ✅ device, ip 추출 (없으면 공백으로)
    device = body.get("device") or ""
    ip = body.get("ip") or ""

    # JWKS 키 로드
    app_key = await get_latest_app_key(db, app.uid)
        
    # 🔒 직렬화 포인트
    await db.execute(
        select(Token)
        .where(
            Token.application_uid == app.uid,
            Token.unique_key == unique_key,
            Token.device == device,
            Token.ip == ip,
        )
        .limit(1)
        .with_for_update()
    )

    # ✅ 기존 토큰 제거 (같은 unique_key + device + ip 조합)
    await db.execute(
        delete(Token).where(
            Token.application_uid == app.uid,
            Token.unique_key == unique_key,
            Token.device == device,
            Token.ip == ip,
        )
    )

    # ✅ JTI 생성
    access_jti = await generate_unique_jti(db)
    refresh_jti = await generate_unique_jti(db)


    # ✅ RSA 개인키로 서명된 JWT 생성
    access_token = create_access_token(
        app.client_id, unique_key, access_jti, app_key.private_key, app_key.kid, config.access_token_expire_minutes
    )
    refresh_token = create_refresh_token(
        app.client_id, unique_key, refresh_jti, app_key.private_key, app_key.kid, config.refresh_token_expire_days
    )

    # ✅ DB 저장
    now = datetime.now(timezone.utc)
    db.add_all([
        Token(
            application_uid=app.uid,
            typ="access",
            jti=access_jti,
            token_hash=hash_password(access_token),
            unique_key=unique_key,
            device=device,
            ip=ip,
            expired_at=now + timedelta(minutes=config.access_token_expire_minutes),
        ),
        Token(
            application_uid=app.uid,
            typ="refresh",
            jti=refresh_jti,
            token_hash=hash_password(refresh_token),
            unique_key=unique_key,
            device=device,
            ip=ip,
            expired_at=now + timedelta(days=config.refresh_token_expire_days),
        ),
    ])
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "kid": app_key.kid,  # 어떤 공개키로 서명됐는지 명시
    }



# ---------------------------------------------------------
# 🔁 Refresh Token 재발급
# ---------------------------------------------------------
@auth_router.post("/refresh")
async def refresh_access_token(request: Request, db: AsyncSession = Depends(get_db)):
    """
    ♻️ Refresh Token을 이용한 토큰 재발급
    """
    # 1️⃣ HMAC 검증
    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")
    app = await verify_hmac_and_get_app(request, db, raw_body)

    # 2️⃣ 요청 본문 파싱
    import json
    try:
        body = json.loads(raw_body)
        token = body.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="Missing refresh token")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # 3️⃣ Refresh Token JWT 검증 및 DB 토큰 조회
    payload, db_token, db_app_key = await verify_jwt_and_get_payload(
        db, app.client_id, token
    )

    unique_key = payload.get("unique_key")
    if not unique_key:
        raise HTTPException(status_code=400, detail="Invalid token payload (missing unique_key)")

    # ✅ 기존 토큰 정보(device, ip, app_uid) 확보
    old_device = db_token.device or ""
    old_ip = db_token.ip or ""
    app_uid = app.uid

    # 5️⃣ 새로운 device, ip 정보 수집
    new_device = body.get("device") or ""
    new_ip = body.get("ip") or ""
    
    # 데드락 방지 직렬화 및 락 처리
    result = await db.execute(
        select(Token)
        .where(Token.jti == db_token.jti)
        .with_for_update()
    )
    locked = result.scalar_one_or_none()
    if not locked:
        raise HTTPException(status_code=401, detail="token already used")

    # 4️⃣ 기존 토큰 폐기 (기존 device/ip 조합 전체 제거) / 중복 토큰 제거
    await db.execute(
        delete(Token).where(
            Token.application_uid == app_uid,
            Token.unique_key == db_token.unique_key,
            (
                (Token.device == old_device) & (Token.ip == old_ip)
                |
                (Token.device == new_device) & (Token.ip == new_ip)
            )
        )
    )

    # 6️⃣ 새로운 AT / RT 생성
    access_jti = await generate_unique_jti(db)
    refresh_jti = await generate_unique_jti(db)

    new_access = create_access_token(
        app.client_id,
        unique_key,
        access_jti,
        db_app_key.private_key,
        db_app_key.kid,
        config.access_token_expire_minutes,
    )
    new_refresh = create_refresh_token(
        app.client_id,
        unique_key,
        refresh_jti,
        db_app_key.private_key,
        db_app_key.kid,
        config.refresh_token_expire_days,
    )

    # 7️⃣ 새 토큰 DB 저장
    now = datetime.now(timezone.utc)
    db.add_all([
        Token(
            application_uid=app_uid,
            typ="access",
            jti=access_jti,
            unique_key=unique_key,
            device=new_device,
            ip=new_ip,
            token_hash=hash_password(new_access),
            expired_at=now + timedelta(minutes=config.access_token_expire_minutes),
        ),
        Token(
            application_uid=app_uid,
            typ="refresh",
            jti=refresh_jti,
            unique_key=unique_key,
            device=new_device,
            ip=new_ip,
            token_hash=hash_password(new_refresh),
            expired_at=now + timedelta(days=config.refresh_token_expire_days),
        ),
    ])

    await db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "kid": db_app_key.kid,
    }


# ---------------------------------------------------------
# ✅ AccessToken 유효성 검증 (/auth/verify)
# ---------------------------------------------------------
@auth_router.post("/verify")
async def verify_token(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Access Token 유효성 검증용 엔드포인트
    - Authorization 헤더에서 Bearer 토큰 추출
    - JWT에서 client_id를 파싱 후 DB에서 공개키 조회
    - 공개키로 JWT 서명 및 만료 검증
    """

    # 1️⃣ body 포함 HMAC 검증
    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")
    app = await verify_hmac_and_get_app(request, db, raw_body)

    # 2️⃣ 요청 파싱
    try:
        body = json.loads(raw_body)
        token = body.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="Missing access token")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # 3️⃣ Access Token JWT 검증
    payload, db_token, db_app_key = await verify_jwt_and_get_payload(
        db, app.client_id, token
    )
    
    return {
        "valid": True,
        "client_id": app.client_id,
        "payload": payload,
        "kid": db_app_key.kid,
    }


# ---------------------------------------------------------
# 🔄 토큰 폐기 (JWT 기반)
# ---------------------------------------------------------
@auth_router.post("/revoke")
async def revoke_token(request: Request, db: AsyncSession = Depends(get_db)):
    """
    ✅ 토큰 폐기 (Access / Refresh)
    - 요청 본문에 JWT 문자열 목록(token)을 받습니다.
    - 각 토큰을 검증 후 DB에서 해당 기록을 삭제합니다.
    - 모든 토큰은 JWT 자체로 typ(at/rt)과 unique_key를 판별합니다.

    요청 예시:
    {
        "token": [
            "<access_token>",
            "<refresh_token>"
        ]
    }
    """
    # 1️⃣ 요청 본문 읽기
    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")

    # 2️⃣ HMAC 서명 검증 → 클라이언트 앱 정보 조회
    app = await verify_hmac_and_get_app(request, db, raw_body)

    # 3️⃣ JSON 파싱
    try:
        body = json.loads(raw_body)
        token_list = body.get("token", [])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not token_list or not isinstance(token_list, list):
        raise HTTPException(status_code=400, detail="Missing or invalid 'token' field")

    total_count = len(token_list)
    deleted_total = 0
    success_tokens: list[str] = []
    failed_tokens: list[dict] = []

    # 4️⃣ 각 토큰 검증 및 폐기
    for jwt_token in token_list:
        try:
            # JWT 검증 → payload, DB token, app_key 조회
            payload, db_token, app_key = await verify_jwt_and_get_payload(
                db=db,
                client_id=app.client_id,
                token=jwt_token,
            )

            unique_key = payload.get("unique_key")
            if not unique_key:
                raise ValueError("Missing unique_key in token payload")

            # DB 삭제
            result = await db.execute(
                delete(Token).where(
                    Token.application_uid == app.uid,
                    Token.unique_key == unique_key,
                    Token.jti == db_token.jti,
                )
            )

            count = result.rowcount or 0
            if count == 0:
                raise ValueError(f"No matching token found (typ={db_token.typ}, unique_key={unique_key})")

            deleted_total += count
            success_tokens.append(jwt_token)

        except Exception as e:
            failed_tokens.append({
                "token": jwt_token,
                "error": str(e),
            })

    await db.commit()

    return {
        "revoked": deleted_total > 0,
        "total_count": total_count,
        "deleted_count": deleted_total,
        "success": success_tokens,
        "failed": failed_tokens,
    }



# ---------------------------------------------------------
# 🔑 JWKS (JSON Web Key Set)
# ---------------------------------------------------------
@auth_router.get("/{client_id}/jwks")
async def get_jwks(client_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Application).where(Application.client_id == client_id))
    app = result.scalars().first()
    if not app:
        raise HTTPException(status_code=404, detail="Invalid client_id")

    # ✅ 아직 만료되지 않은 키만 조회
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(ApplicationKey)
        .where(ApplicationKey.application_uid == app.uid)
        .where((ApplicationKey.expired_at.is_(None)) | (ApplicationKey.expired_at > now))
        .order_by(ApplicationKey.created_at.desc())
    )
    keys = result.scalars().all()
    if not keys:
        raise HTTPException(status_code=404, detail="No active keys found")

    jwks = []
    for k in keys:
        try:
            pubkey = serialization.load_pem_public_key(
                k.public_key.encode("utf-8") if isinstance(k.public_key, str) else k.public_key
            )
            if not isinstance(pubkey, rsa.RSAPublicKey):
                continue
            numbers = pubkey.public_numbers()
            jwks.append({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": k.kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            })
        except Exception:
            continue

    if not jwks:
        raise HTTPException(status_code=500, detail="Failed to build JWKS")

    return JSONResponse(content={"keys": jwks})



# ---------------------------------------------------------
# 🔄 클라이언트 RSA 키 교체 (Key Rotation)
# ---------------------------------------------------------
@auth_router.post("/rotate-key")
async def rotate_client_key(request: Request, db: AsyncSession = Depends(get_db)):
    """
    클라이언트별 RSA 키 교체 (Key Rotation)
    - rotate_after: 분 단위로 설정 (숫자만)
      ex) 0 → 즉시 교체, 10 → 10분 뒤 교체
    """
    # 1️⃣ body 포함 HMAC 검증
    body_bytes = await request.body()
    raw_body = body_bytes.decode("utf-8")
    app = await verify_hmac_and_get_app(request, db, raw_body)

    # 2️⃣ body 파싱
    try:
        body = json.loads(raw_body) if raw_body else {}
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    rotate_after = body.get("rotate_after")

    # 3️⃣ rotate_after 검증 및 변환 (분 단위)
    try:
        if rotate_after is None:
            minutes = 0
        else:
            minutes = int(rotate_after)
            if minutes < 0:
                raise ValueError
    except ValueError:
        raise HTTPException(status_code=400, detail="rotate_after must be a non-negative integer (minutes)")

    offset = timedelta(minutes=minutes)

    # 4️⃣ 기존 키 조회 (최신)
    result = await db.execute(
        select(ApplicationKey)
        .where(ApplicationKey.application_uid == app.uid)
        .order_by(ApplicationKey.created_at.desc())
        .limit(1)
    )
    old_key = result.scalars().first()
    if not old_key:
        raise HTTPException(status_code=404, detail="No existing key found")

    # 5️⃣ 새 키쌍 생성
    new_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = new_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = new_rsa.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    new_kid = _generate_kid()
    now = datetime.now(timezone.utc)

    # 6️⃣ 기존 키 만료 시점 설정
    if minutes == 0:
        old_key.expired_at = now
    else:
        old_key.expired_at = now + offset

    # 7️⃣ 새 키 저장 (offset이 0이면 즉시 활성)
    new_key = ApplicationKey(
        application_uid=app.uid,
        kid=new_kid,
        alg="RS256",
        use="sig",
        public_key=public_pem,
        private_key=private_pem,
        created_at=now,
        expired_at=None,
    )

    db.add(new_key)
    await db.commit()

    return {
        "message": "RSA key rotation successful",
        "rotate_after_minutes": minutes,
        "old_kid": old_key.kid,
        "new_kid": new_kid,
        "effective_at": "immediate" if minutes == 0 else (now + offset).isoformat(),
    }


