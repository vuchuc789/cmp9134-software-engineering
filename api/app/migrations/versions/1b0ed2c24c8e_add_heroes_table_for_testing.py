"""Add heroes table for testing

Revision ID: 1b0ed2c24c8e
Revises: 
Create Date: 2025-03-02 22:42:52.707784

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

# revision identifiers, used by Alembic.
revision: str = '1b0ed2c24c8e'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'heroes', sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('age', sa.Integer(), nullable=True),
        sa.Column('secret_name',
                  sqlmodel.sql.sqltypes.AutoString(),
                  nullable=False), sa.PrimaryKeyConstraint('id'))
    op.create_index(op.f('ix_heroes_age'), 'heroes', ['age'], unique=False)
    op.create_index(op.f('ix_heroes_name'), 'heroes', ['name'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_heroes_name'), table_name='heroes')
    op.drop_index(op.f('ix_heroes_age'), table_name='heroes')
    op.drop_table('heroes')
    # ### end Alembic commands ###
