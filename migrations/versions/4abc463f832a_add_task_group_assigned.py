 
from alembic import op
import sqlalchemy as sa
revision = '4abc463f832a'
down_revision = '91eaacecb322'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('group',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=120), nullable=False),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_table('task',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('title', sa.String(length=120), nullable=False),
                    sa.Column('description', sa.Text(), nullable=True),
                    sa.Column('done', sa.Boolean(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_table('assigned_task',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('user_id', sa.Integer(), nullable=True),
                    sa.Column('task_id', sa.Integer(), nullable=True),
                    sa.ForeignKeyConstraint(['task_id'], ['task.id'], ),
                    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
                    sa.PrimaryKeyConstraint('id')
                    )


def downgrade():
    op.alter_column('user', 'is_active',
                    existing_type=sa.BOOLEAN(),
                    nullable=True)
    op.drop_table('assigned_task')
    op.drop_table('task')
    op.drop_table('group')
