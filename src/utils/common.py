# src/admin/router.py
import re, ipaddress
from datetime import datetime


# ---------------------------------------------------------
# ✅ IP 형식 검증 (예외 X → True / False 반환)
# ---------------------------------------------------------
def validate_ip(ip: str) -> bool:
    """
    IPv4, IPv6, CIDR, Range 형식 검증
    유효하면 True, 잘못된 형식이면 False
    """
    if not isinstance(ip, str):
        return False

    ip = ip.strip()
    if not ip:
        return False

    try:
        if "~" in ip or "-" in ip:  # Range
            start, end = re.split("[-~]", ip)
            ipaddress.ip_address(start.strip())
            ipaddress.ip_address(end.strip())
        elif "/" in ip:  # CIDR
            ipaddress.ip_network(ip, strict=False)
        else:  # 단일 IP
            ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


# ---------------------------------------------------------
# ✅ 공백만 체크 (null 은 False로 처리)
# ---------------------------------------------------------
def is_only_whitespace(value: str) -> bool:
    """
    문자열이 존재하며, 공백 문자만으로 이루어진 경우 True
    """
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"\s+", value))


# ---------------------------------------------------------
# ✅ 공백 + None 체크
# ---------------------------------------------------------
def is_blank(value) -> bool:
    """
    값이 None이거나, 문자열일 때 공백 문자만으로 이루어진 경우 True
    """
    if value is None:
        return True
    if isinstance(value, str):
        return bool(re.fullmatch(r"\s*", value))
    return False


# ---------------------------------------------------------
# ✅ 텍스트가 datetime 형식인지 확인
# ---------------------------------------------------------
def is_datetime_string(value: str) -> bool:
    """
    문자열이 날짜/시간 형식(YYYY-MM-DD HH:mm:ss 등)에 해당하면 True 반환
    지원 포맷:
      - 2025-10-31 05:34:27
      - 2025-10-31T05:34:27
      - 2025.10.31 05:34:27
      - 2025/10/31 05:34:27
    """
    if not isinstance(value, str):
        return False

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y.%m.%d",
        "%Y/%m/%d",
    ]
    for fmt in formats:
        try:
            datetime.strptime(value.strip(), fmt)
            return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------
# ✅ 문자열을 datetime 객체로 변환 (변환 실패 시 None)
# ---------------------------------------------------------
def to_datetime(value):
    """
    문자열을 datetime 객체로 변환
    - 문자열이 datetime 포맷이면 datetime 객체 반환
    - None 또는 공백이면 None 반환
    - 실패 시 None 반환
    """
    if not value or not isinstance(value, str):
        return None

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y.%m.%d",
        "%Y/%m/%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def get_internal_base_url(request, config):
    scheme = request.url.scheme               # http / https
    host = request.url.hostname               # 192.168.2.54
    port = request.url.port                   # None, 80, 443, 8000 등

    # 기본 base host
    if port in (80, 443, None):
        base = f"{str(scheme)}://{str(host)}"
    else:
        base = f"{str(scheme)}://{str(host)}:{str(port)}"

    # 로컬 환경 → prefix 붙이지 않음
    if config.environment == "loc":
        return base

    # dev/liv → prefix(app_name) 붙임
    prefix = config.app_name.lstrip("/")
    return f"{base}/{str(prefix)}"