#!/usr/bin/env python3
import argparse
import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / 'config.json'

def main():
    ap = argparse.ArgumentParser(description='Purge ModScan database tables safely')
    ap.add_argument('--db', help='Path to DB (overrides config.json)')
    ap.add_argument('--purge-vulns', action='store_true', help='Delete all vulnerability rows')
    ap.add_argument('--purge-api-assets', action='store_true', help='Delete old fake API assets (*/dvwa/vulnerabilities/api/*)')
    ap.add_argument('--vacuum', action='store_true', help='VACUUM after deletes')
    args = ap.parse_args()

    cfg = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    db_path = args.db or cfg.get('database_path') or str(BASE_DIR / 'lean_recon.db')

    if not (args.purge_vulns or args.purge_api_assets):
        print('Nothing to do. Pass --purge-vulns and/or --purge-api-assets')
        return

    print(f"Using DB: {db_path}")
    with sqlite3.connect(db_path) as db:
        cur = db.cursor()
        if args.purge_vulns:
            cur.execute("DELETE FROM vulnerabilities;")
            try:
                cur.execute("DELETE FROM sqlite_sequence WHERE name='vulnerabilities';")
            except Exception:
                pass
            print('✅ Purged vulnerabilities table')
        if args.purge_api_assets:
            try:
                cur.execute("DELETE FROM assets WHERE url LIKE '%/dvwa/vulnerabilities/api/%';")
                print('✅ Purged old fake API assets')
            except Exception as e:
                print(f'Note: could not purge fake API assets: {e}')
        if args.vacuum:
            try:
                cur.execute('VACUUM;')
                print('✅ VACUUM complete')
            except Exception:
                pass
        db.commit()

if __name__ == '__main__':
    main()

