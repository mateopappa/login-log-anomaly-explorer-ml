"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-23
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "datasets",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("dataset_id", sa.String(length=128), sa.ForeignKey("datasets.id"), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("country_code", sa.String(length=8), nullable=False),
        sa.UniqueConstraint("dataset_id", "event_id", name="uq_dataset_event"),
    )
    op.create_index("ix_events_dataset_id", "events", ["dataset_id"])
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_account_id", "events", ["account_id"])
    op.create_index("ix_events_timestamp_utc", "events", ["timestamp_utc"])

    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("dataset_id", sa.String(length=128), sa.ForeignKey("datasets.id"), nullable=False),
        sa.Column("case_kind", sa.String(length=32), nullable=False),
        sa.Column("priority_hint", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("event_ids_json", sa.JSON(), nullable=False),
        sa.Column("signals_json", sa.JSON(), nullable=False),
        sa.Column("associations_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_cases_dataset_id", "cases", ["dataset_id"])

    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("case_id", sa.String(length=128), sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("provider_id", sa.String(length=128), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("config_version", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("steps", sa.Integer(), nullable=False),
        sa.Column("errors_json", sa.JSON(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=True),
        sa.Column("tokens_out", sa.Integer(), nullable=True),
        sa.Column("cost_usd_est", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("idempotency_key", name="uq_run_idempotency"),
    )
    op.create_index("ix_investigation_runs_case_id", "investigation_runs", ["case_id"])
    op.create_index("ix_investigation_runs_status", "investigation_runs", ["status"])

    op.create_table(
        "tool_calls",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(length=128), sa.ForeignKey("investigation_runs.id"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("arguments_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
    )
    op.create_index("ix_tool_calls_run_id", "tool_calls", ["run_id"])

    op.create_table(
        "investigation_results",
        sa.Column("run_id", sa.String(length=128), sa.ForeignKey("investigation_runs.id"), primary_key=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("hypotheses_json", sa.JSON(), nullable=False),
    )

    op.create_table(
        "reviews",
        sa.Column("run_id", sa.String(length=128), sa.ForeignKey("investigation_runs.id"), primary_key=True),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("quality", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
    )

    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("metrics_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("evaluation_runs")
    op.drop_table("reviews")
    op.drop_table("investigation_results")
    op.drop_table("tool_calls")
    op.drop_table("investigation_runs")
    op.drop_table("cases")
    op.drop_table("events")
    op.drop_table("datasets")
