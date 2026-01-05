# src/utils/history.py
import json
from typing import Optional
from fastapi import Request
from starlette.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from src.user.models import User, UserHistory

SENSITIVE_KEYS = {"password", "password_verify"}


def sanitize_data(data: dict | None) -> dict | None:
    """민감정보 키를 마스킹"""
    if not data:
        return None
    safe_data = {}
    for key, value in data.items():
        if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
            safe_data[key] = "***"
        else:
            safe_data[key] = value
    return safe_data


async def _get_request_body_json(request: Request) -> Optional[dict]:
    """요청 body를 JSON으로 안전하게 변환"""
    try:
        if hasattr(request.state, "body_raw"):
            raw = request.state.body_raw
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    return None


async def record_user_history(
    db: AsyncSession,
    request: Request,
    response: Response,
    user: User | None = None,
    *,
    memo: str = "",
    capture_body: bool = False,
    max_body_bytes: int = 2048,
):
    """
    ✅ 요청 / 응답 로그를 UserHistory(req_*, res_*) 구조에 맞게 저장
    - request: method, headers, body, query
    - response: status, headers, body(optional)
    """
    ip_address = request.client.host if request.client else "unknown"
    url = str(request.url.path)

    # ✅ 요청 정보
    headers_req = dict(request.headers)
    body_req = await _get_request_body_json(request)
    query_req = dict(request.query_params) if request.query_params else None

    # ✅ 응답 메타
    status_res = getattr(response, "status_code", None)
    headers_res = dict(getattr(response, "headers", {}))

    # ✅ 응답 본문 (필요시만)
    body_res_text: Optional[str] = None
    if capture_body:
        try:
            body_bytes = getattr(response, "body", b"")
            if not body_bytes:
                if hasattr(response, "body_iterator") and response.body_iterator is not None:
                    chunks = []
                    async for chunk in response.body_iterator:
                        chunks.append(chunk)
                        if sum(len(c) for c in chunks) >= max_body_bytes:
                            break
                    body_bytes = b"".join(chunks)
                    async def _async_iter_bytes(body: bytes):
                        yield body

                    response.body_iterator = _async_iter_bytes(body_bytes)
            if body_bytes:
                body_res_text = body_bytes[:max_body_bytes].decode("utf-8", errors="ignore")
        except Exception:
            body_res_text = None

    # ✅ UserHistory 인스턴스 생성 (새 구조 반영)
    history = UserHistory(
        user_uid=user.uid if user else None,
        ip_address=ip_address,
        url=url,
        memo=memo,

        # 요청
        req_method=request.method,
        req_header=sanitize_data(headers_req),
        req_body=sanitize_data(body_req) if body_req else None,
        req_query=sanitize_data(query_req) if query_req else None,

        # 응답
        res_status=status_res,
        res_header=headers_res,
        res_body=body_res_text if capture_body else None,
    )

    db.add(history)
    await db.commit()
