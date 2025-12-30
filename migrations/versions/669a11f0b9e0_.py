 
from alembic import op
import sqlalchemy as sa
revision = '669a11f0b9e0'
down_revision = '0763d677d453'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_active')


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('is_active', sa.BOOLEAN(), nullable=False))
