# Auth Service (FastAPI)

이 프로젝트는 **클라이언트 애플리케이션별(Client ID)로 JWT를 발급/검증/갱신/폐기**하는 인증 서비스입니다.  
요청 무결성 검증을 위해 **HMAC 서명**을 사용하고, 토큰 자체는 **RSA 개인키로 서명된 JWT**로 발급되며, 공개키는 **JWKS 엔드포인트**로 제공합니다.

또한 관리자 페이지(템플릿 + Tailwind CSS 빌드)를 통해 애플리케이션 등록/관리 및 키 로테이션 등을 운영할 수 있도록 구성되어 있습니다.
관리자 페이지는 아직 개발중입니다.

---

## 핵심 기능

- **토큰 발급**: `POST /auth/token`
  - HMAC 검증
  - unique_key + device + ip 기준으로 기존 토큰 정리 후 재발급
- **토큰 갱신**: `POST /auth/refresh`
- **토큰 검증**: `POST /auth/verify`
- **토큰 폐기(로그아웃)**: `POST /auth/revoke`
- **JWKS 제공**: `GET /auth/{client_id}/jwks`
- **키 로테이션**: `POST /auth/rotate-key`
- **관리자(Admin) UI**: 애플리케이션/키 관리 화면(Jinja2 templates + Tailwind)

---

## 기술 스택

- FastAPI + Uvicorn
- SQLAlchemy Async + Alembic(마이그레이션)
- JOSE(JWT), Cryptography(RSA 키)
- Jinja2 templates / Static files
- Tailwind CSS(빌드 스크립트 포함)

---

## 프로젝트 구조(요약)

- `src/main.py` : FastAPI 엔트리, 예외 핸들러/정적/템플릿 마운트, 라우터 등록
- `src/auth/router.py` : 인증 API(`/token`, `/refresh`, `/verify`, `/revoke`, `/jwks`, `/rotate-key`)
- `src/admin/router.py` : 관리자 화면/관리 API
- `src/database.py` : Async DB 세션/엔진
- `src/config.py` : Pydantic Settings (.env.{ENVIRONMENT} 로드)
- `alembic/` : DB 마이그레이션
- `templates/`, `static/` : 관리자 UI
- `package.json` : Tailwind CSS 빌드 스크립트

---

## 실행 방법 (Docker Compose)

```bash
docker compose up --build
```

- Host `8080` → Container `80`

compose에서 컨테이너 시작 시 아래 커맨드를 수행합니다.

- `alembic upgrade head`
- `uvicorn src.main:app --host 0.0.0.0 --port 80`

---

## 환경 변수(.env.{ENVIRONMENT})

`src/config.py` 기준으로 설정이 필요합니다. (예: `.env.loc`, `.env.dev`, `.env.prod`)

필수(대표):
- `APP_NAME`
- `ENVIRONMENT` (예: `loc`)
- `LOGGING_LEVEL`
- `TIMEZONE`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `REFRESH_TOKEN_EXPIRE_DAYS`
- `CLIENT_ID`
- `CLIENT_SECRET`

DB(Main):
- `DB_MAIN_HOST`
- `DB_MAIN_PORT`
- `DB_MAIN_USER`
- `DB_MAIN_PASSWORD`
- `DB_MAIN_NAME`

> ⚠️ 실제 운영에서는 `.env`를 Git에 올리지 말고, 배포 환경 Secret으로 주입하는 방식을 권장합니다.

---

## API 개요

### 1) POST `/auth/token`
- 토큰 발급(Access/Refresh)
- HMAC 검증을 통과해야 함
- unique_key/device/ip 기반으로 기존 토큰 정리 후 재발급

### 2) POST `/auth/refresh`
- Refresh 토큰 기반 Access 토큰 재발급(및 필요 시 Refresh 재발급)

### 3) POST `/auth/verify`
- 토큰 유효성 검증

### 4) POST `/auth/revoke`
- 토큰(또는 토큰 목록) 폐기

### 5) GET `/auth/{client_id}/jwks`
- 해당 client_id의 JWKS(공개키) 제공

### 6) POST `/auth/rotate-key`
- 키 로테이션
