# src/utils/security.py
from __future__ import annotations

# ==============================================================
# 📦 공통 import
# ==============================================================
from typing import Callable, Optional
import hmac
import hashlib
import httpx
import json
import base64
import uuid
import ipaddress
import random
import string
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response, Depends, HTTPException
from jose import jwt, JWTError, ExpiredSignatureError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from src.database import get_db
from src.user.models import User
from src.app.models import Application, ApplicationKey, Token
from src.exceptions import NotAuthenticatedException
from src.config import get_settings
from src.utils.common import get_internal_base_url


# ==============================================================
# ⚙️ 기본 설정
# ==============================================================
ALGORITHM = "RS256"
config = get_settings()


# ==============================================================
# 🔐 PASSWORD / HMAC 관련 유틸
# ==============================================================
_BCRYPTO_AVAILABLE = False
_bcrypto_hash_func: Optional[Callable[..., str]] = None
_bcrypto_verify_func: Optional[Callable[..., bool]] = None

try:
    # 1) bcrypto가 설치되어 있으면 우선 사용
    import bcrypto  # type: ignore

    if hasattr(bcrypto, "hash"):
        _bcrypto_hash_func = getattr(bcrypto, "hash")
    elif hasattr(bcrypto, "hash_password"):
        _bcrypto_hash_func = getattr(bcrypto, "hash_password")

    if hasattr(bcrypto, "verify"):
        _bcrypto_verify_func = getattr(bcrypto, "verify")
    elif hasattr(bcrypto, "verify_password"):
        _bcrypto_verify_func = getattr(bcrypto, "verify_password")

    _BCRYPTO_AVAILABLE = _bcrypto_hash_func is not None and _bcrypto_verify_func is not None
except Exception:
    _BCRYPTO_AVAILABLE = False

# 2) bcrypto가 없거나 인터페이스를 찾지 못하면 bcrypt로 폴백
if not _BCRYPTO_AVAILABLE:
    import bcrypt  # type: ignore


def hash_password(plain: str, *, rounds: int = 12) -> str:
    """
    비밀번호 해시 생성 (bcrypto 우선, 실패 시 bcrypt 폴백)
    - rounds: cost factor (기본 12)
    """
    if plain is None:
        raise ValueError("Password cannot be None")
    if not isinstance(plain, str):
        raise TypeError("Password must be a string")

    if _BCRYPTO_AVAILABLE and _bcrypto_hash_func:
        try:
            hashed = _bcrypto_hash_func(plain, rounds=rounds)  # type: ignore[arg-type]
        except TypeError:
            hashed = _bcrypto_hash_func(plain)  # type: ignore[misc]
        if not isinstance(hashed, str):
            hashed = hashed.decode("utf-8") if isinstance(hashed, (bytes, bytearray)) else str(hashed)
        return hashed

    salt = bcrypt.gensalt(rounds=rounds)
    hashed_b = bcrypt.hashpw(plain.encode("utf-8"), salt)
    return hashed_b.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """
    평문 비밀번호와 저장된 해시 일치 여부 확인 (bcrypto 우선, 실패 시 bcrypt 폴백)
    """
    if not hashed or plain is None:
        return False

    if _BCRYPTO_AVAILABLE and _bcrypto_verify_func:
        try:
            return bool(_bcrypto_verify_func(plain, hashed))
        except TypeError:
            try:
                return bool(_bcrypto_verify_func(hashed, plain))  # type: ignore[misc]
            except Exception:
                return False
        except Exception:
            return False

    try:
        import bcrypt
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


async def verify_hmac_and_get_app(
    request: Request,
    db: AsyncSession,
    raw_body: str | None = None
) -> Application:
    """
    ✅ 클라이언트 요청의 HMAC 서명을 검증하고 Application 반환
    - 헤더: X-Client-Id, X-Signature 필수
    - body에 timestamp 포함, UTC 기준 ±5분 이내만 유효
    - body는 UTF-8 → base64 인코딩된 문자열을 message로 사용
    """
    # ───────────────────────────────────────────────
    # ① 헤더 검증
    # ───────────────────────────────────────────────
    client_id = request.headers.get("X-Client-Id")
    signature = request.headers.get("X-Signature")

    if not client_id or not signature:
        raise HTTPException(status_code=401, detail="Missing HMAC headers")

    # ───────────────────────────────────────────────
    # ② body 존재 및 timestamp 추출
    # ───────────────────────────────────────────────
    if raw_body is None:
        raise HTTPException(status_code=400, detail="Missing request body for HMAC verification")

    try:
        body_data = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    timestamp_val = body_data.get("timestamp")
    if timestamp_val is None:
        raise HTTPException(status_code=400, detail="Missing timestamp in body")

    # ✅ timestamp가 정수(UNIX)인지 ISO 문자열인지 자동 판별
    try:
        if isinstance(timestamp_val, (int, float)):  # UNIX timestamp (예: 1734449982)
            req_time = datetime.fromtimestamp(timestamp_val, tz=timezone.utc)
        elif isinstance(timestamp_val, str):
            # ISO 형식일 수도 있음 (ex: "2025-10-17T08:20:00Z")
            try:
                req_time = datetime.strptime(timestamp_val, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid timestamp format (expected UNIX or ISO8601)")
        else:
            raise HTTPException(status_code=400, detail="Invalid timestamp type")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timestamp value")

    now = datetime.now(timezone.utc)
    if abs((now - req_time).total_seconds()) > 300:
        raise HTTPException(status_code=401, detail="Request timestamp expired (±5 min limit)")

    # ───────────────────────────────────────────────
    # ③ 클라이언트 인증정보 조회
    # ───────────────────────────────────────────────
    result = await db.execute(select(Application).where(Application.client_id == client_id))
    app = result.scalars().first()
    if not app:
        raise HTTPException(status_code=401, detail="Invalid client_id")

    if not app.client_secret:
        raise HTTPException(status_code=401, detail="Client has no secret key")
    
    
    # ───────────────────────────────────────────────
    # ④ 클라이언트 IP 검증 (IPv4, IPv6, CIDR, Subnet Mask 지원)
    # ───────────────────────────────────────────────
    def is_ip_allowed(client_ip: str, allowed_list: list[str]) -> bool:
        """IPv4 / IPv6 / CIDR / Mask / Range(10.0.0.1-10.0.0.10) 지원"""
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid client IP format: {client_ip}")

        for entry in allowed_list:
            entry = entry.strip()

            # ✅ Range (10.10.100.22~10.10.100.25 or 10.10.100.22-10.10.100.25)
            if "~" in entry or "-" in entry:
                sep = "~" if "~" in entry else "-"
                start_ip_str, end_ip_str = [x.strip() for x in entry.split(sep, 1)]
                try:
                    start_ip = ipaddress.ip_address(start_ip_str)
                    end_ip = ipaddress.ip_address(end_ip_str)
                    if start_ip.version == client_ip_obj.version and start_ip <= client_ip_obj <= end_ip:
                        return True
                except ValueError:
                    continue

            # ✅ CIDR or Subnet Mask
            elif "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if client_ip_obj in network:
                        return True
                except ValueError:
                    continue

            # ✅ 단일 IP
            else:
                if client_ip == entry:
                    return True

        return False
    # ───────────────────────────────────────────────
    # 실제 사용
    # ───────────────────────────────────────────────
    client_ip = request.headers.get("X-Forwarded-For") or (request.client.host if request.client else None)

    if app.allowed_ips:
        try:
            allowed_list = json.loads(app.allowed_ips) if isinstance(app.allowed_ips, str) else app.allowed_ips
        except Exception:
            raise HTTPException(status_code=500, detail="Invalid allowed_ips format in DB")

        if not client_ip:
            raise HTTPException(status_code=400, detail="Client IP not detected")

        if not is_ip_allowed(client_ip, allowed_list):
            raise HTTPException(status_code=403, detail=f"Access denied for IP: {client_ip}")

    # ───────────────────────────────────────────────
    # ⑤ HMAC 검증 (body → utf-8 → base64 인코딩)
    # ───────────────────────────────────────────────
    message = raw_body.encode("utf-8")
    expected_signature = base64.b64encode(
        hmac.new(app.client_secret.encode("utf-8"), message, hashlib.sha256).digest()
    ).decode()

    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    return app


async def verify_jwt_and_get_payload(
    db: AsyncSession,
    client_id: str,
    token: str,
):
    """
    ✅ JWT(Access/Refresh) 검증 공통 함수
    - client_id로 공개키 조회
    - JWT decode 및 typ/claim 검증
    - DB에 등록된 jti 일치 확인

    반환: (payload, db_token, app_key)
    """

    # 🔑 1) 최신 공개키 조회
    result = await db.execute(
        select(ApplicationKey)
        .join(Application, Application.uid == ApplicationKey.application_uid)
        .where(Application.client_id == client_id)
        .order_by(ApplicationKey.created_at.desc())
        .limit(1)
    )
    app_key = result.scalar_one_or_none()
    if not app_key or not app_key.public_key:
        raise HTTPException(status_code=401, detail="No public key found for client")

    # 🧩 2) JWT Decode
    try:
        payload = jwt.decode(token, app_key.public_key, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # 📋 3) 필수 필드 확인
    unique_key = payload.get("unique_key")
    jti = payload.get("jti")
    typ = payload.get("typ")  # ✅ typ 자동 판별 (access / refresh)

    if not all([unique_key, jti, typ]):
        raise HTTPException(status_code=400, detail="Missing required claims in token")

    if typ not in ("access", "refresh"):
        raise HTTPException(status_code=401, detail="Invalid token type")

    # 🧾 4) DB에서 토큰 일치 확인
    result = await db.execute(
        select(Token)
        .where(Token.jti == jti)
        .order_by(Token.created_at.desc())
    )
    db_token = result.scalars().first()

    if not db_token:
        raise HTTPException(status_code=401, detail=f"No valid {typ} token found")

    if db_token.jti != jti:
        raise HTTPException(status_code=401, detail=f"{typ.capitalize()} token does not match stored record")

    return payload, db_token, app_key



# ==============================================================
# 🍪 TokenCookieManager (쿠키 기반 AT/RT 관리)
# ==============================================================
class TokenCookieManager:
    """
    ✅ JWT AccessToken / RefreshToken을 HttpOnly 쿠키로 안전하게 관리

    - AccessToken / RefreshToken을 클라이언트 쿠키에 저장할 때 HttpOnly 보호 적용
    - JWT의 exp 클레임에서 만료시간을 자동 계산하여 max_age 설정
    - SameSite 옵션 설명:
        * "Strict" → 기본값. 외부 사이트에서 요청 시 쿠키 전송 금지 (보안성 최고)
        * "Lax" → 일부 안전한 cross-site 요청(GET 등) 허용
        * "None" → 완전한 cross-site 쿠키 허용 (단, 반드시 Secure=True 필요)
    """

    def __init__(
        self,
        at_name: str = ("" if config.environment == "liv" else config.environment + "_") + "access_token",
        rt_name: str = ("" if config.environment == "liv" else config.environment + "_") + "refresh_token",
        remember_me_name: str = ("" if config.environment == "liv" else config.environment + "_") + "remember_me",
        *,
        secure: bool = False,
        httponly: bool = True,
        samesite: str = "Lax",
        domain: Optional[str] = "localhost" if config.environment == "loc" else "192.168.2.54",
        path: str = "/",
        at_max_age: int = 60 * 15,  # 5분
        rt_max_age: int = 60 * 60 * 24 * 30,  # 30일
    ):
        self.at_name = at_name
        self.rt_name = rt_name
        self.remember_me_name = remember_me_name
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite
        self.domain = domain
        self.path = path
        self.at_max_age = at_max_age
        self.rt_max_age = rt_max_age

    # ---------------------------------------------------------
    # ✅ 쿠키 설정 (JWT exp 기준 자동 만료)
    # ---------------------------------------------------------
    def set_tokens(self, request: Request, response: Response, access_token: str, refresh_token: Optional[str] = None, remember_me: Optional[bool] = None) -> None:
        """
        JWT의 exp 클레임 기준으로 max_age 자동 계산 후 쿠키에 저장
        """
        def get_max_age(token: str) -> Optional[int]:
            try:
                # JWT 디코드 (서명 검증 없이 exp만 추출)
                payload = jwt.decode(token, None, options={"verify_signature": False})
                exp = payload.get("exp")
                if not exp:
                    return None
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                remaining = (exp_dt - datetime.now(timezone.utc)).total_seconds()
                return max(int(remaining), 0)
            except Exception:
                return None

        at_max_age = get_max_age(access_token)
        rt_max_age = get_max_age(refresh_token) if refresh_token else None

        cookie_remember = None
        if request is not None:
            try:
                cookie_remember = bool(request.cookies.get("remember_me"))
            except Exception:
                cookie_remember = False
        remember_me = remember_me if remember_me is not None else bool(cookie_remember)
        
        if not remember_me:
            at_max_age = None
            rt_max_age = None

        response.set_cookie(
            key=self.at_name,
            value=access_token,
            httponly=self.httponly,
            secure=self.secure,
            samesite=self.samesite,
            domain=self.domain,
            path=self.path,
            max_age=at_max_age,
        )

        if refresh_token:
            response.set_cookie(
                key=self.rt_name,
                value=refresh_token,
                httponly=self.httponly,
                secure=self.secure,
                samesite=self.samesite,
                domain=self.domain,
                path=self.path,
                max_age=rt_max_age,
            )

        response.set_cookie(
            key=self.remember_me_name,
            value=remember_me,
            httponly=self.httponly,
            secure=self.secure,
            samesite=self.samesite,
            domain=self.domain,
            path=self.path,
            max_age=rt_max_age,
        )

    # ---------------------------------------------------------
    # ✅ 쿠키 조회
    # ---------------------------------------------------------
    def get_tokens(self, request: Request) -> dict[str, Optional[str]]:
        return {
            "access_token": request.cookies.get(self.at_name),
            "refresh_token": request.cookies.get(self.rt_name),
            "remember_me": request.cookies.get(self.remember_me_name),
        }

    # ---------------------------------------------------------
    # ✅ 쿠키 삭제
    # ---------------------------------------------------------
    def clear_tokens(self, response: Response) -> None:
        response.delete_cookie(key=self.at_name, domain=self.domain, path=self.path)
        response.delete_cookie(key=self.rt_name, domain=self.domain, path=self.path)
        response.delete_cookie(key=self.remember_me_name, domain=self.domain, path=self.path)


# ==============================================================
# 🔑 RSA Key (JWKS) 관련
# ==============================================================
async def get_latest_app_key(db: AsyncSession, app_uid: int) -> ApplicationKey:
    result = await db.execute(
        select(ApplicationKey)
        .where(ApplicationKey.application_uid == app_uid)
        .order_by(ApplicationKey.created_at.desc())
        .limit(1)
    )
    key = result.scalars().first()
    if not key:
        raise HTTPException(status_code=500, detail="No RSA key found for this application.")
    return key


async def get_public_key(db: AsyncSession) -> str:
    result = await db.execute(
        select(ApplicationKey.public_key)
        .order_by(ApplicationKey.created_at.desc())
        .limit(1)
    )
    public_key = result.scalar_one_or_none()
    if not public_key:
        raise HTTPException(status_code=500, detail="No public key found")
    return public_key


# ==============================================================
# 🧮 JWT 생성 (RSA private key 서명)
# ==============================================================
# ✅ jti 중복 검사 (access/refresh 모두)
async def generate_unique_jti(db: AsyncSession):
    """yyyyMMdd-uuid 형태로 유일한 JTI 생성"""
    while True:
        date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
        new_jti = f"{date_prefix}-{uuid.uuid4()}"
        result = await db.execute(select(Token).where(Token.jti == new_jti))
        if not result.scalars().first():
            return new_jti
        
def create_jwt(data: dict, expires: timedelta, private_key: str, kid: str) -> str:
    payload = data.copy()
    payload["exp"] = int((datetime.now(timezone.utc) + expires).timestamp())
    return jwt.encode(
        payload,
        private_key,
        algorithm=ALGORITHM,
        headers={"kid": kid}
    )


def create_access_token(client_id: str, unique_key: str, jti: str, private_key: str, kid: str, minutes: int = 5) -> str:
    """AccessToken 생성"""
    return create_jwt(
        {"sub": client_id, "unique_key": unique_key, "typ": "access", "jti": jti},
        timedelta(minutes=minutes),
        private_key,
        kid=kid,
    )


def create_refresh_token(client_id: str, unique_key: str, jti: str, private_key: str, kid: str, days: int = 7) -> str:
    """RefreshToken 생성"""
    return create_jwt(
        {"sub": client_id, "unique_key": unique_key, "typ": "refresh", "jti": jti},
        timedelta(days=days),
        private_key,
        kid=kid,
    )




# ==============================================================
# 🔍 JWT 검증 (JWKS 기반)
# ==============================================================
def _rsa_key_from_jwk(jwk: dict) -> rsa.RSAPublicKey:
    """JWKS dict → RSAPublicKey 객체 변환"""
    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    return pub_numbers.public_key(default_backend())

async def fetch_public_key_from_jwks(request: Request, client_id: str) -> Optional[str]:
    """/auth/{client_id}/jwks 에서 공개키 가져오기"""
    try:
        async with httpx.AsyncClient(base_url=get_internal_base_url(request, config)) as client:
            resp = await client.get(f"/auth/{client_id}/jwks")
        if resp.status_code != 200:
            return None

        data = resp.json()
        keys = data.get("keys", [])
        return keys if isinstance(keys, list) else None

    except Exception:
        return None


async def decode_jwt_via_jwks(request: Request, token: str) -> Optional[dict]:
    """
    JWKS 배열에서 kid 기반으로 공개키 선택 후 JWT 검증
    """
    keys = await fetch_public_key_from_jwks(request, config.client_id)
    if not keys:
        return None

    # ① JWT header에서 kid 추출
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
    except JWTError:
        return None

    # ② kid 매칭되는 JWK 찾기
    match = None
    if kid:
        for jwk in keys:
            if jwk.get("kid") == kid:
                match = jwk
                break

    # ③ fallback: kid 없거나 매칭 실패
    if match is None:
        return None

    # ④ JWK → PEM 변환
    try:
        pub_key = _rsa_key_from_jwk(match)
        pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except Exception:
        return None

    # ⑤ JWT 검증
    try:
        payload = jwt.decode(token, pem, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ==============================================================
# 🔍 JWT 검증 (HMAC 서명 + /auth/verify API)
# ==============================================================
async def decode_jwt_via_hmac(request: Request, token: str) -> Optional[dict]:
    """
    ✅ /auth/verify 호출을 통한 JWT 검증
    - HMAC 서명 포함 (X-Client-Id, X-Signature)
    - 내부 인증 서버에 위임 검증
    """
    try:
        timestamp = int(datetime.now(timezone.utc).timestamp())

        # ✅ body 생성
        verify_body = {
            "token": token,
            "timestamp": timestamp,
        }
        raw_body = json.dumps(verify_body, ensure_ascii=False)
        message = raw_body.encode("utf-8")

        # ✅ HMAC signature 생성
        signature = base64.b64encode(
            hmac.new(
                config.client_secret.encode("utf-8"),
                message,
                hashlib.sha256,
            ).digest()
        ).decode()

        headers = {
            "Content-Type": "application/json",
            "X-Client-Id": config.client_id,
            "X-Signature": signature,
        }

        async with httpx.AsyncClient(base_url=get_internal_base_url(request, config)) as client:
            resp = await client.post("/auth/verify", content=raw_body, headers=headers)

        if resp.status_code != 200:
            return None

        data = resp.json()
        payload = data.get("payload")
        return payload if payload and payload.get("unique_key") else None

    except Exception as e:
        print(f"[decode_jwt_via_hmac] 검증 실패: {e}")
        return None



# ==============================================================
# 🧍 사용자 쿠키 기반 인증
# ==============================================================
async def get_current_user_from_cookie(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    ✅ 쿠키 기반 사용자 검증 (JWKS 원격 검증)
    - AccessToken → sub(client_id)로 JWKS 조회 후 검증
    - unique_key로 사용자 식별
    - Refresh 시 AT/RT 모두 쿠키에 재저장
    """
    token_mgr = TokenCookieManager()
    tokens = token_mgr.get_tokens(request)
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    timestamp = int(datetime.now(timezone.utc).timestamp())
    
    if access_token:

        # ① AccessToken 검증 (로컬 JWKS 검증)
        payload = await decode_jwt_via_jwks(request, access_token)
        if payload and payload.get("unique_key"):
            return await _get_user_by_unique_key(db, payload["unique_key"])

        # # ② JWKS 실패 시 HMAC 기반 검증 API 호출
        # payload = await decode_jwt_via_hmac(request, access_token)
        # if payload and payload.get("unique_key"):
        #     return await _get_user_by_unique_key(db, payload["unique_key"])

    # ③ Refresh Token 갱신 시도
    if refresh_token:
        try:
            device = config.environment + "_" + (request.headers.get("X-Device") or request.headers.get("User-Agent") or "unknown")
            ip = request.client.host or ""
            
            # ✅ body 구성
            body = {
                "token": refresh_token,
                "device": device,
                "ip": ip,
                "timestamp": timestamp,
            }

            # ✅ JSON 직렬화
            raw_body = json.dumps(body, ensure_ascii=False)

            # ✅ HMAC message = body.encode("utf-8")
            message = raw_body.encode("utf-8")

            # ✅ signature = base64(HMAC_SHA256(secret, message))
            signature = base64.b64encode(
                hmac.new(
                    config.client_secret.encode("utf-8"),
                    message,
                    hashlib.sha256,
                ).digest()
            ).decode()

            # ✅ /auth/refresh 호출 (HMAC 헤더 포함)
            headers = {
                "Content-Type": "application/json",
                "X-Client-Id": config.client_id,
                "X-Signature": signature,
            }

            # ✅ /auth/refresh 호출 (HMAC 헤더 포함)
            async with httpx.AsyncClient(base_url=get_internal_base_url(request, config)) as client:
                resp = await client.post(
                    "/auth/refresh",
                    content=raw_body,
                    headers=headers,
                )

            if resp.status_code != 200:
                return None

            data = resp.json()
            
            new_access_token = data.get("access_token")
            new_refresh_token = data.get("refresh_token")

            # ✅ 새로운 AT로 유저 검증
            payload = await decode_jwt_via_jwks(request, new_access_token)
            if not payload or not payload.get("unique_key"):
                return None
            
            # payload = await decode_jwt_via_hmac(request, access_token)
            # if payload and payload.get("unique_key"):
            #     return await _get_user_by_unique_key(db, payload["unique_key"])
            

            # ✅ 새 토큰 쿠키에 저장
            from fastapi import Response
            response = Response()
            token_mgr.set_tokens(request, response, new_access_token, new_refresh_token)
            request.state._cookie_refresh_response = response


            return await _get_user_by_unique_key(db, payload["unique_key"])

        except Exception:
            return None


async def _get_user_by_unique_key(db: AsyncSession, unique_key: str) -> Optional[User]:
    """DB에서 unique_key로 사용자 조회"""
    result = await db.execute(select(User).where(User.uid == unique_key))
    return result.scalars().first()




# ---------------------------------------------------------------------
# 🔐 Utility functions
# ---------------------------------------------------------------------
def generate_client_id() -> str:
    """랜덤 숫자 10자리 client_id 생성"""
    return ''.join(random.choices(string.digits, k=10))


def generate_hashed_key() -> str:
    """랜덤 32자 문자열을 sha256 해시"""
    raw = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_rsa_keypair() -> tuple[str, str]:
    """RSA 2048bit 키쌍 생성 (PEM 문자열 반환)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def generate_kid() -> str:
    """KID = 날짜(YYYYMMDD) + UUID4"""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{today}-{uuid.uuid4()}"