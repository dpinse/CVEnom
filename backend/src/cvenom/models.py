from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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
        Index("ix_story_content_hash", "content_hash"),
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


class GeoEvent(Base):
    __tablename__ = "geo_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String)
    external_id: Mapped[str] = mapped_column(String)
    kind: Mapped[str] = mapped_column(String)
    country_code: Mapped[str | None] = mapped_column(String(2))
    asn: Mapped[int | None] = mapped_column(BigInteger)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    magnitude: Mapped[float] = mapped_column(Float, default=1.0, server_default="1")
    label: Mapped[str | None] = mapped_column(Text)
    cve_id: Mapped[str | None] = mapped_column(String)  # reference only: no FK
    story_url: Mapped[str | None] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_geo_event_source_external_id"),
        Index("ix_geo_event_observed_at_brin", "observed_at", postgresql_using="brin"),
        Index("ix_geo_event_country_kind", "country_code", "kind"),
    )
