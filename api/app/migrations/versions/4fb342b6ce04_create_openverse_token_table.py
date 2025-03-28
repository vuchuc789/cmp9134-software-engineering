"""Create Openverse token table

Revision ID: 4fb342b6ce04
Revises: 4e5bad1fca24
Create Date: 2025-03-20 14:23:22.812302

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4fb342b6ce04'
down_revision: str | None = '4e5bad1fca24'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'openverse_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('access_token', sa.String(), nullable=False),
        sa.Column('expires_in', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('openverse_tokens')
    # ### end Alembic commands ###
