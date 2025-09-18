#!/usr/bin/env python3
"""
Backfill canonical_key for existing vulnerabilities rows that are NULL.
Uses AssetManager._generate_canonical_vuln_key to ensure consistency.
Safe to run multiple times.
"""
from datetime import datetime
import sqlite3
from asset_manager import AssetManager, VulnerabilityFinding


def main(db_path: str = None):
    am = AssetManager()
    if db_path is None:
        db_path = am.db_path

    updated = 0
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT v.id, v.type, v.evidence, v.payload, v.detected_at, v.canonical_key,
                   a.url as asset_url
            FROM vulnerabilities v
            LEFT JOIN assets a ON v.asset_id = a.id
            WHERE v.canonical_key IS NULL OR v.canonical_key = ''
            """
        ).fetchall()

        for r in rows:
            try:
                vf = VulnerabilityFinding(
                    url=r["asset_url"] or "",
                    vuln_type=r["type"] or "",
                    severity="Info",
                    confidence=0.0,
                    payload=r["payload"] or "",
                    evidence=r["evidence"] or "",
                    discovered_at=datetime.now(),
                )
                key = am._generate_canonical_vuln_key(vf, r["asset_url"] or "")
                if key:
                    db.execute(
                        "UPDATE vulnerabilities SET canonical_key=? WHERE id=?",
                        (key, int(r["id"]))
                    )
                    updated += 1
            except Exception:
                continue
        db.commit()
    print(f"Backfill complete. Updated {updated} rows with canonical_key.")


if __name__ == "__main__":
    main()

