# src/cache_utils.py
"""
FastAPI Static Files Caching Utilities

다양한 환경에 적합한 캐싱 전략을 제공하는 StaticFiles 클래스들과 헬퍼 함수들
"""

from fastapi.staticfiles import StaticFiles
from fastapi import HTTPException, APIRouter
from starlette.types import Scope, Receive, Send
from pathlib import Path
import hashlib
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class NoCacheStaticFiles(StaticFiles):
    """
    캐시를 방지하는 스태틱파일 클래스
    개발 환경에서 파일 변경사항을 즉시 반영하기 위해 사용
    """
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_no_cache_headers(message):
            if message["type"] == "http.response.start":
                # 캐시 방지 헤더 추가
                headers = list(message.get("headers", []))
                
                # 기존 캐시 관련 헤더 제거
                headers = [h for h in headers if h[0].lower() not in [
                    b'cache-control', b'etag', b'last-modified', b'expires'
                ]]
                
                # 캐시 방지 헤더 추가
                headers.extend([
                    (b'cache-control', b'no-cache, no-store, must-revalidate'),
                    (b'pragma', b'no-cache'),
                    (b'expires', b'0'),
                ])
                
                message["headers"] = headers
            
            await send(message)
        
        await super().__call__(scope, receive, send_with_no_cache_headers)


class VersionedStaticFiles(StaticFiles):
    """
    Cache Busting을 지원하는 스태틱파일 클래스
    파일 해시 기반으로 ETag 생성 및 조건부 캐싱 지원
    """
    def __init__(self, *args, max_age: int = 300, **kwargs):  # 기본 5분 캐시
        super().__init__(*args, **kwargs)
        self.max_age = max_age
        self._file_hashes: Dict[str, str] = {}
    
    def _get_file_hash(self, file_path: Path) -> str:
        """파일의 MD5 해시를 계산합니다."""
        if not file_path.exists():
            return ""
        
        # 파일 수정 시간을 포함한 키 생성
        stat = file_path.stat()
        cache_key = f"{file_path}:{stat.st_mtime}"
        
        if cache_key not in self._file_hashes:
            try:
                with open(file_path, 'rb') as f:
                    self._file_hashes[cache_key] = hashlib.md5(f.read()).hexdigest()[:8]
            except:
                self._file_hashes[cache_key] = str(int(stat.st_mtime))
        
        return self._file_hashes[cache_key]
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_cache_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                
                # 파일 경로 추출
                path = scope.get("path", "").lstrip("/static/")
                if path:
                    file_path = Path(self.directory) / path
                    
                    # ETag 생성 (파일 해시 기반)
                    etag = self._get_file_hash(file_path)
                    if etag:
                        # 기존 캐시 헤더 제거
                        headers = [h for h in headers if h[0].lower() not in [
                            b'cache-control', b'etag', b'expires'
                        ]]
                        
                        # 새로운 캐시 헤더 추가
                        headers.extend([
                            (b'cache-control', f'public, max-age={self.max_age}'.encode()),
                            (b'etag', f'"{etag}"'.encode()),
                        ])
                        
                        # If-None-Match 헤더 확인 (304 응답)
                        if_none_match = None
                        for name, value in scope.get("headers", []):
                            if name == b"if-none-match":
                                if_none_match = value.decode()
                                break
                        
                        # ETag가 일치하면 304 Not Modified 응답
                        if if_none_match and f'"{etag}"' in if_none_match:
                            message["status"] = 304
                            headers = [(b'etag', f'"{etag}"'.encode())]
                
                message["headers"] = headers
            
            await send(message)
        
        await super().__call__(scope, receive, send_with_cache_headers)


class SmartCacheStaticFiles(StaticFiles):
    """
    파일 타입별 차별 캐싱을 지원하는 스태틱파일 클래스
    """
    CACHE_RULES = {
        # 자주 변경되는 파일들 - 짧은 캐시
        '.css': 300,    # 5분
        '.js': 300,     # 5분
        '.html': 60,    # 1분
        
        # 거의 변경되지 않는 파일들 - 긴 캐시
        '.png': 86400,   # 1일
        '.jpg': 86400,   # 1일
        '.jpeg': 86400,  # 1일
        '.gif': 86400,   # 1일
        '.ico': 86400,   # 1일
        '.woff': 86400,  # 1일
        '.woff2': 86400, # 1일
        '.ttf': 86400,   # 1일
    }
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_smart_cache_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                
                # 파일 확장자에 따른 캐시 시간 설정
                path = scope.get("path", "")
                file_ext = Path(path).suffix.lower()
                max_age = self.CACHE_RULES.get(file_ext, 300)  # 기본 5분
                
                # 기존 캐시 헤더 제거
                headers = [h for h in headers if h[0].lower() not in [
                    b'cache-control', b'expires'
                ]]
                
                # 새로운 캐시 헤더 추가
                headers.extend([
                    (b'cache-control', f'public, max-age={max_age}'.encode()),
                ])
                
                message["headers"] = headers
            
            await send(message)
        
        await super().__call__(scope, receive, send_with_smart_cache_headers)


def get_static_files_class(environment: str):
    """
    환경에 따라 적절한 StaticFiles 클래스를 반환
    
    Args:
        environment: 'loc', 'dev', 'liv' 중 하나
        
    Returns:
        StaticFiles 클래스 인스턴스
    """
    if environment in ['loc']:
        # 로컬 환경: 즉시 반영을 위한 NoCache
        logger.info("NoCacheStaticFiles 적용됨 (로컬 환경)")
        return NoCacheStaticFiles
    elif environment in ['dev']:
        # 개발 환경: 짧은 캐시 + ETag 기반 조건부 캐싱
        logger.info("VersionedStaticFiles 적용됨 (개발 환경, 5분 캐시)")
        return lambda directory: VersionedStaticFiles(directory=directory, max_age=300)
    else:  # liv (live/production)
        # 운영 환경: 파일 타입별 차별 캐싱
        logger.info("⚡ SmartCacheStaticFiles 적용됨 (운영 환경, 파일별 차별 캐싱)")
        return SmartCacheStaticFiles


def get_file_version_hash(file_path: str, static_dir: str = "./static") -> dict:
    """
    파일의 버전 해시를 계산하여 반환
    
    Args:
        file_path: 정적 파일 경로 (예: "css/main.css")
        static_dir: 정적 파일 디렉토리 경로
        
    Returns:
        {"version": "해시값", "url": "버전이 포함된 URL"}
        
    Raises:
        HTTPException: 파일이 존재하지 않을 때
    """
    file_full_path = Path(static_dir) / file_path
    if not file_full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    stat = file_full_path.stat()
    try:
        with open(file_full_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()[:8]
    except Exception:
        file_hash = str(int(stat.st_mtime))
    
    return {
        "version": file_hash, 
        "url": f"/static/{file_path}?v={file_hash}"
    }


def create_cache_busting_router(static_dir: str = "./static") -> APIRouter:
    """
    Cache Busting API 라우터를 생성합니다.
    필요시 main.py에서 app.include_router(create_cache_busting_router()) 로 사용
    
    Args:
        static_dir: 정적 파일 디렉토리 경로
        
    Returns:
        APIRouter: Cache busting API가 포함된 라우터
        
    Example:
        from src.cache_utils import create_cache_busting_router
        app.include_router(create_cache_busting_router(), prefix="/api")
    """
    router = APIRouter()
    
    @router.get("/static-version/{file_path:path}")
    async def get_static_file_version(file_path: str):
        """
        프론트엔드에서 사용할 수 있는 파일 버전 API
        사용 예: /api/static-version/css/main.css -> {"version": "abc123"}
        """
        return get_file_version_hash(file_path, static_dir)
    
    return router 