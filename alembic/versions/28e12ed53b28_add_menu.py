"""add menu

Revision ID: 28e12ed53b28
Revises: 30bd8ec8e9d0
Create Date: 2025-10-15 11:06:17.249093
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '28e12ed53b28'
down_revision: Union[str, None] = '30bd8ec8e9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- create table ---
    op.create_table(
        'menus',
        sa.Column('uid', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('icon', sa.String(length=50), nullable=True),
        sa.Column('url', sa.String(length=255), nullable=True),
        sa.Column('parent_uid', sa.Integer(), nullable=True),
        sa.Column('order', sa.Integer(), nullable=False, server_default="0"),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default=sa.text("1")),
        sa.Column('visible_roles', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['parent_uid'], ['menus.uid']),
        sa.PrimaryKeyConstraint('uid')
    )

    # --- insert default seed data ---
    menus_table = sa.table(
        'menus',
        sa.column('name', sa.String),
        sa.column('icon', sa.String),
        sa.column('url', sa.String),
        sa.column('parent_uid', sa.Integer),
        sa.column('order', sa.Integer),
        sa.column('is_active', sa.Boolean),
        sa.column('visible_roles', sa.Text),
    )

    # ✅ 부모 → 자식 순서로 삽입 (uid 자동 증가)
    op.bulk_insert(
        menus_table,
        [
            # ---------------------
            # 1️⃣ Root Menus
            # ---------------------
            {"name": "Admin", "icon": "shield", "url": None, "parent_uid": None, "order": 1, "is_active": True, "visible_roles": "ADMIN"},
            {"name": "Support", "icon": "life-buoy", "url": None, "parent_uid": None, "order": 2, "is_active": True, "visible_roles": None},
            {"name": "Application", "icon": "app-window", "url": None, "parent_uid": None, "order": 3, "is_active": True, "visible_roles": "USER"},
            {"name": "User", "icon": "user", "url": None, "parent_uid": None, "order": 4, "is_active": True, "visible_roles": "USER"},

            # ---------------------
            # 2️⃣ Admin Children
            # ---------------------
            {"name": "대시보드", "icon": "layout-dashboard", "url": "/admin/dashboard", "parent_uid": 1, "order": 1, "is_active": True, "visible_roles": "ADMIN"},
            {"name": "사용자 관리", "icon": "users", "url": "/admin/users", "parent_uid": 1, "order": 2, "is_active": True, "visible_roles": "ADMIN,ADMIN_USER"},
            {"name": "애플리케이션 관리", "icon": "cpu", "url": "/admin/apps", "parent_uid": 1, "order": 3, "is_active": True, "visible_roles": "ADMIN,ADMIN_APPLICATION"},
            {"name": "메뉴 관리", "icon": "list", "url": "/admin/menus", "parent_uid": 1, "order": 4, "is_active": True, "visible_roles": "ADMIN,ADMIN_MENU"},
            {"name": "게시판 관리", "icon": "clipboard-list", "url": "/admin/boards", "parent_uid": 1, "order": 5, "is_active": True, "visible_roles": "ADMIN,ADMIN_BOARD"},

            # ---------------------
            # 3️⃣ Support Children
            # ---------------------
            {"name": "문서", "icon": "book-open", "url": "/support/docs", "parent_uid": 2, "order": 1, "is_active": True, "visible_roles": None},
            {"name": "1:1 문의", "icon": "messages-square", "url": "/support/inquiry", "parent_uid": 2, "order": 2, "is_active": True, "visible_roles": None},
            {"name": "커뮤니티", "icon": "users-round", "url": "/support/community", "parent_uid": 2, "order": 3, "is_active": True, "visible_roles": None},

            # ---------------------
            # 4️⃣ Application Children
            # ---------------------
            {"name": "내 애플리케이션", "icon": "layers", "url": "/app/list", "parent_uid": 3, "order": 1, "is_active": True, "visible_roles": None},

            # ---------------------
            # 5️⃣ User Children
            # ---------------------
            {"name": "내 정보", "icon": "user-circle", "url": "/user/mypage", "parent_uid": 4, "order": 1, "is_active": True, "visible_roles": "USER"},
            {"name": "비밀번호 변경", "icon": "key-round", "url": "/user/password", "parent_uid": 4, "order": 2, "is_active": True, "visible_roles": "USER"},
        ]
    )


def downgrade() -> None:
    op.drop_table('menus')
