"""Initial event, case, approval and append-only audit tables."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "observations",
        sa.Column("evidence_id", sa.String(64), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    for column in ["timestamp", "src_ip", "dst_ip"]:
        op.create_index("ix_observations_" + column, "observations", [column])
    op.create_table(
        "cases",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=True),
    )
    op.create_index("ix_cases_status", "cases", ["status"])
    op.create_table(
        "approvals",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("plan_hash", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.UniqueConstraint("case_id", "plan_hash"),
    )
    op.create_table(
        "audit",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("run_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False, unique=True),
        sa.Column("previous", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_run_id", "audit", ["run_id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE FUNCTION forbid_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit is append-only'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation()"
        )


def downgrade():
    raise RuntimeError("destructive audit downgrade intentionally unsupported")
