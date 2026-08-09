from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JsonType = JSONB().with_variant(JSON(), "sqlite")


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    license: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(ForeignKey("sources.name"), index=True)
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    title: Mapped[str | None] = mapped_column(Text)
    body_text: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_path: Mapped[str | None] = mapped_column(Text)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    license: Mapped[str] = mapped_column(String(32))


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"))
    primary_attack_type: Mapped[str | None] = mapped_column(String(64), index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Float)
    extraction_version: Mapped[str] = mapped_column(String(32))
    extracted_by: Mapped[str] = mapped_column(String(16))
    extra: Mapped[dict | None] = mapped_column(JsonType)

    __table_args__ = (
        UniqueConstraint(
            "document_id", "extraction_version", "extracted_by", name="uq_record_version"
        ),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_v3: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    epss: Mapped[float | None] = mapped_column(Float)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)


class CrawlRun(Base):
    __tablename__ = "crawl_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    fetched: Mapped[int] = mapped_column(Integer, default=0)
    parsed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="running")
    note: Mapped[str | None] = mapped_column(Text)


class FetchError(Base):
    __tablename__ = "fetch_errors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text)
    error_class: Mapped[str] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    last_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("source", "url", name="uq_fetch_error_url"),)


class Actor(Base):
    __tablename__ = "actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    aliases: Mapped[dict | None] = mapped_column(JsonType)


class Technique(Base):
    __tablename__ = "techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # e.g. "T1566"
    name: Mapped[str] = mapped_column(Text)
    tactic: Mapped[str | None] = mapped_column(Text)


class Sector(Base):
    __tablename__ = "sectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class AttackType(Base):
    __tablename__ = "attack_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class Ioc(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text, index=True)

    __table_args__ = (UniqueConstraint("document_id", "type", "value", name="uq_ioc"),)


class DocumentCve(Base):
    __tablename__ = "document_cves"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True, index=True)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentActor(Base):
    __tablename__ = "document_actors"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("actors.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentTechnique(Base):
    __tablename__ = "document_techniques"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(ForeignKey("techniques.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentSector(Base):
    __tablename__ = "document_sectors"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[int] = mapped_column(ForeignKey("sectors.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


class DocumentAttackType(Base):
    __tablename__ = "document_attack_types"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    attack_type_id: Mapped[int] = mapped_column(ForeignKey("attack_types.id"), primary_key=True)
    confidence: Mapped[float | None] = mapped_column(Float)
    matched_text: Mapped[str | None] = mapped_column(Text)


Index("ix_documents_source_published", Document.source, Document.published_at)
