"""add_rate_limit_rpm_to_api_keys

Revision ID: 89a1b2c3d4e5
Revises: 76f86cc3e87b
Create Date: 2026-09-20 15:58:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '89a1b2c3d4e5'
down_revision: Union[str, Sequence[str], None] = '76f86cc3e87b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add rate_limit_rpm with default 60
    with op.batch_alter_table('api_keys') as batch_op:
        batch_op.add_column(sa.Column('rate_limit_rpm', sa.Integer(), nullable=False, server_default='60'))


def downgrade() -> None:
    with op.batch_alter_table('api_keys') as batch_op:
        batch_op.drop_column('rate_limit_rpm')
