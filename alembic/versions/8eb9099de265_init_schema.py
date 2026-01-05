"""init schema + 기본 데이터 삽입

Revision ID: 8eb9099de265
Revises:
Create Date: 2025-09-24 08:03:15.399344

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
import bcrypt

# revision identifiers, used by Alembic.
revision: str = "8eb9099de265"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### 테이블 생성 ###
    op.create_table(
        "role",
        sa.Column("uid", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("uid"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "user",
        sa.Column("uid", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("pw", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.Enum("USE", "DEL", "WAIT", name="userstatus"), default="WAIT", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("uid"),
    )
    # 🔹 아이디는 단순 인덱스만 (unique 제거)
    op.create_index(op.f("ix_user_id"), "user", ["id"], unique=False)
    op.create_index(op.f("ix_user_uid"), "user", ["uid"], unique=False)

    op.create_table(
        "user_history",
        sa.Column("uid", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_uid", sa.Integer(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("url", sa.String(length=255), nullable=True),
        sa.Column("memo", sa.String(length=50), nullable=False),

        # ✅ 요청(Request) 정보
        sa.Column("req_method", sa.String(length=10), nullable=True),
        sa.Column("req_header", sa.JSON(), nullable=True),
        sa.Column("req_body", sa.JSON(), nullable=True),
        sa.Column("req_query", sa.JSON(), nullable=True),

        # ✅ 응답(Response) 정보
        sa.Column("res_status", sa.Integer(), nullable=True),
        sa.Column("res_header", sa.JSON(), nullable=True),
        sa.Column("res_body", sa.JSON(), nullable=True),

        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),

        sa.ForeignKeyConstraint(["user_uid"], ["user.uid"]),
        sa.PrimaryKeyConstraint("uid"),
    )

    op.create_table(
        "user_role",
        sa.Column("user_uid", sa.Integer(), nullable=False),
        sa.Column("role_uid", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["role_uid"], ["role.uid"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_uid"], ["user.uid"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_uid", "role_uid"),
    )

    # ✅ 기본 Role 삽입
    roles = [
        ("ADMIN", "관리자 권한"),
        ("ADMIN_USER", "관리자 사용자 제어 권한"),
        ("ADMIN_MENU", "관리자 메뉴 제어 권한"),
        ("ADMIN_BOARD", "관리자 게시판 제어 권한"),
        ("ADMIN_APPLICATION", "관리자 어플리케이션 제어 권한"),
        ("USER", "사용자 권한"),
    ]
    for name, desc in roles:
        op.execute(f"""
            INSERT INTO role (name, description)
            SELECT '{name}', '{desc}'
            WHERE NOT EXISTS (SELECT 1 FROM role WHERE name='{name}')
        """)

    # ✅ 기본 관리자 계정 생성
    hashed_pw = bcrypt.hashpw("test".encode("utf-8"), bcrypt.gensalt()).decode()
    op.execute(f"""
        INSERT INTO user (id, pw, name, status)
        SELECT 'kjh', '{hashed_pw}', '관리자', 'USE'
        WHERE NOT EXISTS (SELECT 1 FROM user WHERE id='kjh')
    """)

    # ✅ 관리자에게 모든 권한 부여
    for name, _ in roles:
        op.execute(f"""
            INSERT INTO user_role (user_uid, role_uid)
            SELECT u.uid, r.uid
            FROM user u, role r
            WHERE u.id='kjh' AND r.name='{name}'
            AND NOT EXISTS (
                SELECT 1 FROM user_role ur
                JOIN user uu ON ur.user_uid = uu.uid
                JOIN role rr ON ur.role_uid = rr.uid
                WHERE uu.id='kjh' AND rr.name='{name}'
            )
        """)


def downgrade() -> None:
    # ### 테이블 제거 ###
    op.drop_table("user_role")
    op.drop_table("user_history")
    op.drop_index(op.f("ix_user_uid"), table_name="user")
    op.drop_index(op.f("ix_user_id"), table_name="user")
    op.drop_table("user")
    op.drop_table("role")
