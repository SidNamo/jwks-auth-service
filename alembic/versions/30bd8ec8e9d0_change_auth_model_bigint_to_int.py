"""update auth models (application_key 추가 및 token 구조 변경 + RSA 시드키 추가)

Revision ID: 30bd8ec8e9d0
Revises: 8eb9099de265
Create Date: 2025-10-14 14:37:14.860219
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session
import random, string, hashlib, uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# revision identifiers, used by Alembic.
revision: str = '30bd8ec8e9d0'
down_revision: Union[str, None] = '8eb9099de265'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------
# 🔐 Utility functions
# ---------------------------------------------------------------------
def _generate_client_id() -> str:
    """랜덤 숫자 10자리 client_id 생성"""
    return ''.join(random.choices(string.digits, k=10))


def _generate_hashed_key() -> str:
    """랜덤 32자 문자열을 sha256 해시"""
    raw = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return hashlib.sha256(raw.encode()).hexdigest()


def _generate_rsa_keypair() -> tuple[str, str]:
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


def _generate_kid() -> str:
    """KID = 날짜(YYYYMMDD) + UUID4"""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{today}-{uuid.uuid4()}"


# ---------------------------------------------------------------------
# 🔼 Upgrade
# ---------------------------------------------------------------------
def upgrade() -> None:
    # ✅ application 테이블
    op.create_table(
        'application',
        sa.Column('uid', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('client_secret', sa.String(length=255), nullable=True),
        sa.Column('allowed_ips', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('uid'),
        sa.UniqueConstraint('client_id'),
    )
    op.create_index('ix_application_name', 'application', ['name'], unique=False)

    # ✅ application_collaborator
    op.create_table(
        'application_collaborator',
        sa.Column('application_uid', sa.Integer(), nullable=False),
        sa.Column('user_uid', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['application_uid'], ['application.uid'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_uid'], ['user.uid'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('application_uid', 'user_uid'),
    )

    # ✅ application_key
    op.create_table(
        'application_key',
        sa.Column('application_uid', sa.Integer(), sa.ForeignKey('application.uid', ondelete='CASCADE'), nullable=False),
        sa.Column('kid', sa.String(length=128), nullable=False),
        sa.Column('alg', sa.String(length=32), nullable=False, server_default='RS256'),
        sa.Column('use', sa.String(length=16), nullable=False, server_default='sig'),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('private_key', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('application_uid', 'kid'),
        sa.UniqueConstraint('application_uid', 'kid', name='uq_appkey_app_kid'),
    )
    op.create_index('ix_appkey_app', 'application_key', ['application_uid'], unique=False)

    # ✅ token (최신 구조)
    op.create_table(
        'token',
        sa.Column('application_uid', sa.Integer(), sa.ForeignKey('application.uid', ondelete='CASCADE'), nullable=False),
        sa.Column('unique_key', sa.String(length=128), nullable=False),
        sa.Column('typ', sa.String(length=16), nullable=False),
        sa.Column('device', sa.String(length=255), nullable=False, server_default=""),
        sa.Column('ip', sa.String(length=45), nullable=False, server_default=""),
        sa.Column('jti', sa.String(length=128), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('scope', sa.Text(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('options', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('jti', name='uq_token_jti'),
        sa.UniqueConstraint('application_uid', 'unique_key', 'device', 'ip', 'typ', name='uq_token_app_key_device_ip_typ'),
    )
    op.create_index('ix_token_app', 'token', ['application_uid'], unique=False)
    op.create_index('ix_token_expired_at', 'token', ['expired_at'], unique=False)
    op.create_index('ix_token_unique_key', 'token', ['unique_key'], unique=False)
    op.create_index('ix_token_ip', 'token', ['ip'], unique=False)
    op.create_index('ix_token_device', 'token', ['device'], unique=False)

    # ✅ 초기 데이터 삽입
    bind = op.get_bind()
    session = Session(bind=bind)

    # Default Application 1
    client_id = _generate_client_id()
    client_secret = _generate_hashed_key()

    session.execute(
        sa.text("""
            INSERT INTO application (name, client_id, client_secret, allowed_ips)
            VALUES (:name, :client_id, :client_secret, :allowed_ips)
        """),
        {
            "name": "Default Application",
            "client_id": client_id,
            "client_secret": client_secret,
            "allowed_ips": '["127.0.0.1"]'
        }
    )

    session.execute(
        sa.text("""
            INSERT INTO application_collaborator (application_uid, user_uid)
            VALUES (:application_uid, :user_uid)
        """),
        {"application_uid": 1, "user_uid": 1}
    )

    private_key, public_key = _generate_rsa_keypair()
    kid = _generate_kid()
    session.execute(
        sa.text("""
            INSERT INTO application_key (application_uid, kid, alg, `use`, public_key, private_key, created_at, expired_at)
            VALUES (:application_uid, :kid, :alg, :use, :public_key, :private_key, :created_at, NULL)
        """),
        {
            "application_uid": 1,
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "public_key": public_key,
            "private_key": private_key,
            "created_at": datetime.now(timezone.utc),
        }
    )


    session.commit()
    print("\n✅ Default Applications, Keys, and Collaborators created successfully.\n")


# ---------------------------------------------------------------------
# 🔽 Downgrade
# ---------------------------------------------------------------------
def downgrade() -> None:
    op.drop_index('ix_token_device', table_name='token')
    op.drop_index('ix_token_ip', table_name='token')
    op.drop_index('ix_token_unique_key', table_name='token')
    op.drop_index('ix_token_expired_at', table_name='token')
    op.drop_index('ix_token_app', table_name='token')
    op.drop_table('token')

    op.drop_index('ix_appkey_app', table_name='application_key')
    op.drop_table('application_key')

    op.drop_table('application_collaborator')
    op.drop_index('ix_application_name', table_name='application')
    op.drop_table('application')
