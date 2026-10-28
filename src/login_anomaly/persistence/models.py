"""ORM models. Separated from API response schemas."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class DatasetRow(Base):
    __tablename__ = "datasets"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    events: Mapped[list[EventRow]] = relationship(back_populates="dataset")
    cases: Mapped[list[CaseRow]] = relationship(back_populates="dataset")


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("dataset_id", "event_id", name="uq_dataset_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    account_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    country_code: Mapped[str] = mapped_column(String(8), nullable=False)

    dataset: Mapped[DatasetRow] = relationship(back_populates="events")


class CaseRow(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"), nullable=False, index=True)
    case_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    priority_hint: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    event_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    signals_json: Mapped[list] = mapped_column(JSON, nullable=False)
    associations_json: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    dataset: Mapped[DatasetRow] = relationship(back_populates="cases")
    runs: Mapped[list[InvestigationRunRow]] = relationship(back_populates="case", order_by="InvestigationRunRow.created_at")


class InvestigationRunRow(Base):
    __tablename__ = "investigation_runs"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_run_idempotency"),)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(128), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    config_version: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    steps: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd_est: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Event ids this run judged. Null on rows written before the column existed.
    event_ids_json: Mapped[list | None] = mapped_column(JSON, nullable=True)

    case: Mapped[CaseRow] = relationship(back_populates="runs")
    tool_calls: Mapped[list[ToolCallRow]] = relationship(back_populates="run", order_by="ToolCallRow.seq")
    result: Mapped[InvestigationResultRow | None] = relationship(back_populates="run", uselist=False)
    review: Mapped[ReviewRow | None] = relationship(back_populates="run", uselist=False)


class ToolCallRow(Base):
    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("investigation_runs.id"), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    arguments_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    run: Mapped[InvestigationRunRow] = relationship(back_populates="tool_calls")


class InvestigationResultRow(Base):
    __tablename__ = "investigation_results"

    run_id: Mapped[str] = mapped_column(ForeignKey("investigation_runs.id"), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, nullable=False)
    evidence_json: Mapped[list] = mapped_column(JSON, nullable=False)
    hypotheses_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    run: Mapped[InvestigationRunRow] = relationship(back_populates="result")


class ReviewRow(Base):
    __tablename__ = "reviews"

    run_id: Mapped[str] = mapped_column(ForeignKey("investigation_runs.id"), primary_key=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    quality: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    run: Mapped[InvestigationRunRow] = relationship(back_populates="review")


class EvaluationRunRow(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    metrics_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
