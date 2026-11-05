from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Cve(Base):
    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    kev_added: Mapped[date | None] = mapped_column(Date)
    kev_source: Mapped[str | None] = mapped_column(String)
    poc_badge: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    patch_available: Mapped[bool | None] = mapped_column(Boolean)
    affected: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_cve_published_brin", "published", postgresql_using="brin"),
    )


class Story(Base):
    __tablename__ = "story"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String, unique=True)
    content_hash: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    published: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_story_published_brin", "published", postgresql_using="brin"),
    )


class StoryCveLink(Base):
    __tablename__ = "story_cve_link"

    story_id: Mapped[int] = mapped_column(
        ForeignKey("story.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cve.cve_id", ondelete="CASCADE"), primary_key=True
    )


Index("ix_story_cve_link_cve_id", StoryCveLink.cve_id)


class CollectorRun(Base):
    __tablename__ = "collector_run"

    collector: Mapped[str] = mapped_column(String, primary_key=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
