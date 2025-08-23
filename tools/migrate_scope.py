#!/usr/bin/env python3
"""
Normalize the scope table to schema:
  scope(id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        is_active INTEGER NOT NULL DEFAULT 1)

Run:
  python3 tools/migrate_scope.py
"""
import sqlite3
from asset_manager import AssetManager

def main():
    am = AssetManager()
    with am._get_db() as db:
        cols = {row[1] for row in db.execute("PRAGMA table_info(scope)").fetchall()}
        if cols == {'id','domain','is_active'}:
            print('Scope schema already normalized.')
            return 0
        # Read existing entries
        domains = []
        if 'domain' in cols:
            for (d,) in db.execute('SELECT domain FROM scope').fetchall():
                domains.append(d)
        elif 'target' in cols:
            for (d,) in db.execute('SELECT target FROM scope').fetchall():
                domains.append(d)
        # Create new table
        db.execute('DROP TABLE IF EXISTS scope_new')
        db.execute('CREATE TABLE scope_new (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, is_active INTEGER NOT NULL DEFAULT 1)')
        for d in domains:
            try:
                db.execute('INSERT OR IGNORE INTO scope_new(domain,is_active) VALUES (?,1)', (d,))
            except Exception:
                pass
        db.execute('DROP TABLE IF EXISTS scope')
        db.execute('ALTER TABLE scope_new RENAME TO scope')
        db.commit()
        print(f'Normalized scope schema. Migrated {len(domains)} targets.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

