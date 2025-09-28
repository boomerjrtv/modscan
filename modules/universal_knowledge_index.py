"""Lightweight universal knowledge index for ModScan.

Stores curated vulnerability intelligence in a local SQLite FTS index so the
planner can retrieve relevant playbooks, payloads, and remediation guidance
without depending on target-specific scripting.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class KnowledgeDocument:
    """Normalized knowledge document stored in the index."""

    doc_id: str
    title: str
    category: str
    content: str
    metadata: Dict[str, Any]
    source: str = "manual"
    created_at: datetime = datetime.utcnow()

    def to_row(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.doc_id,
            self.title,
            self.category,
            self.content,
            json.dumps(self.metadata, ensure_ascii=True, separators=(",", ":")),
            self.source,
        )


class UniversalKnowledgeIndex:
    """SQLite-backed knowledge base with FTS retrieval."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        default_path = Path("data") / "knowledge_index.db"
        self.db_path = Path(db_path) if db_path else default_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_docs (
                    doc_id TEXT PRIMARY KEY,
                    title TEXT,
                    category TEXT,
                    content TEXT,
                    metadata TEXT,
                    source TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            db.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    doc_id,
                    title,
                    category,
                    content,
                    metadata,
                    tokenize = 'porter',
                    content = 'knowledge_docs',
                    content_rowid = 'rowid'
                )
                """
            )

            db.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(rowid, doc_id, title, category, content, metadata)
                    VALUES (new.rowid, new.doc_id, new.title, new.category, new.content, new.metadata);
                END;

                CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, doc_id, title, category, content, metadata)
                        VALUES('delete', old.rowid, old.doc_id, old.title, old.category, old.content, old.metadata);
                    INSERT INTO knowledge_fts(rowid, doc_id, title, category, content, metadata)
                        VALUES(new.rowid, new.doc_id, new.title, new.category, new.content, new.metadata);
                END;

                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge_docs BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, doc_id, title, category, content, metadata)
                        VALUES('delete', old.rowid, old.doc_id, old.title, old.category, old.content, old.metadata);
                END;
                """
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def document_count(self) -> int:
        with self._connect() as db:
            (count,) = db.execute("SELECT COUNT(*) FROM knowledge_docs").fetchone()
            return int(count)

    def upsert_document(self, doc: KnowledgeDocument) -> None:
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO knowledge_docs(doc_id, title, category, content, metadata, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
                ON CONFLICT(doc_id) DO UPDATE SET
                    title = excluded.title,
                    category = excluded.category,
                    content = excluded.content,
                    metadata = excluded.metadata,
                    source = excluded.source
                """,
                doc.to_row() + (doc.created_at.isoformat(),),
            )
            db.commit()

    def query(self, query: str, limit: int = 5, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if not query:
            return []

        normalized = self._normalize_query(query)
        params: List[Any] = [normalized, limit]
        where_clause = ""

        if category:
            where_clause = "AND docs.category = ?"
            params.insert(-1, category.lower())

        sql = f"""
            SELECT
                docs.doc_id,
                docs.title,
                docs.category,
                docs.content,
                docs.metadata,
                docs.source,
                bm25(knowledge_fts, 1.2, 0.75) AS score
            FROM knowledge_fts
            JOIN knowledge_docs AS docs ON docs.rowid = knowledge_fts.rowid
            WHERE knowledge_fts MATCH ? {where_clause}
            ORDER BY score ASC
            LIMIT ?
        """

        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            metadata = {}
            try:
                metadata = json.loads(row["metadata"] or "{}")
            except json.JSONDecodeError:
                metadata = {"raw": row["metadata"]}
            results.append(
                {
                    "doc_id": row["doc_id"],
                    "title": row["title"],
                    "category": row["category"],
                    "score": float(row["score"] or 0.0),
                    "content": row["content"],
                    "metadata": metadata,
                    "source": row["source"],
                }
            )
        return results

    # ------------------------------------------------------------------
    # Seeding helpers
    # ------------------------------------------------------------------
    def hydrate_default_corpus(self, base_dir: Optional[Path | str] = None, max_per_category: int = 20) -> int:
        """Populate the index with bundled resources on first run."""
        if self.document_count() > 0:
            return 0

        base = Path(base_dir) if base_dir else Path.cwd()
        payloads_path = base / "ultimate_payloads" / "hackerone_payloads_by_category.json"
        reports_path = base / "hackerone-reports"

        inserted = 0
        if payloads_path.exists():
            try:
                with payloads_path.open("r", encoding="utf-8") as fh:
                    payload_map = json.load(fh)
                for category, payloads in payload_map.items():
                    payload_list = self._coerce_list(payloads)[:max_per_category]
                    if not payload_list:
                        continue
                    body = "\n".join(map(str, payload_list))
                    doc_id = f"payload::{self._slugify(category)}"
                    doc = KnowledgeDocument(
                        doc_id=doc_id,
                        title=f"HackerOne payload exemplars: {category}",
                        category=self._normalize_category(category),
                        content=body,
                        metadata={
                            "payload_count": len(payload_list),
                            "category_raw": category,
                        },
                        source="hackerone_payloads",
                    )
                    self.upsert_document(doc)
                    inserted += 1
            except Exception as exc:  # pragma: no cover - ingestion failures are informational
                logger.warning("Failed seeding payload corpus: %s", exc)

        # Optional: ingest disclosed reports stored as JSON lines
        if reports_path.exists():
            for path in sorted(reports_path.glob("*.json"))[:max_per_category * 2]:
                try:
                    with path.open("r", encoding="utf-8") as fh:
                        report = json.load(fh)
                except Exception:
                    continue
                title = report.get("title") or path.stem
                body_parts = [report.get("weakness_name", ""), report.get("summary", ""), report.get("remediation_advice", "")]
                payloads = report.get("payloads") or []
                if payloads:
                    body_parts.append("Payloads:\n" + "\n".join(map(str, payloads)))
                content = "\n".join(p for p in body_parts if p)
                if not content.strip():
                    continue
                doc = KnowledgeDocument(
                    doc_id=f"report::{path.stem}",
                    title=title,
                    category=self._normalize_category(report.get("weakness_name", "")),
                    content=content,
                    metadata={
                        "severity": report.get("severity_rating"),
                        "bounty": report.get("total_bounty_awarded"),
                        "report_url": report.get("url"),
                    },
                    source="hackerone_disclosures",
                )
                self.upsert_document(doc)
                inserted += 1

        logger.info("Seeded knowledge index with %s documents", inserted)
        return inserted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_query(query: str) -> str:
        query = query.strip()
        if not query:
            return ""
        # Replace overly broad punctuation with spaces to keep FTS happy
        query = re.sub(r"[\"'`]+", " ", query)
        return query

    @staticmethod
    def _normalize_category(value: str) -> str:
        if not value:
            return "generic"
        return re.sub(r"\s+", "_", value.strip().lower())

    @staticmethod
    def _slugify(value: str) -> str:
        value = value.strip().lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        return value.strip("-") or "generic"

    @staticmethod
    def _coerce_list(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (set, tuple)):
            return list(value)
        return [value]


__all__ = ["UniversalKnowledgeIndex", "KnowledgeDocument"]
