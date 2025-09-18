#!/usr/bin/env python3
"""
Import ModScan++ findings from findings.jsonl into the dashboard database
"""
import json
import sqlite3
import sys
from pathlib import Path
from datetime import datetime
from asset_manager import AssetManager, VulnerabilityFinding

BASE_DIR = Path(__file__).resolve().parents[1]
FINDINGS_FILE = BASE_DIR / "findings.jsonl"
DB_PATH = BASE_DIR / "lean_recon.db"

def get_asset_id_by_url(db, url):
    """Find asset_id for a given URL"""
    cursor = db.execute("SELECT id FROM assets WHERE url = ? LIMIT 1", (url,))
    result = cursor.fetchone()
    if result:
        return result[0]
    
    # Try base URL match
    base_url = url.split('?')[0].rstrip('/')
    cursor = db.execute("SELECT id FROM assets WHERE url LIKE ? OR url LIKE ? LIMIT 1", 
                       (f"{base_url}%", f"{base_url}/%"))
    result = cursor.fetchone()
    return result[0] if result else None

def map_severity(severity):
    """Map ModScan++ severity to dashboard format"""
    mapping = {
        "high": "HIGH",
        "medium": "MEDIUM", 
        "low": "LOW",
        "critical": "CRITICAL"
    }
    return mapping.get(severity.lower(), "MEDIUM")

def map_confidence(category):
    """Map vulnerability category to confidence score"""
    mapping = {
        "SSRF": 0.85,
        "XSS": 0.90,
        "Open Redirect": 0.75,
        "Prototype Pollution": 0.70
    }
    return mapping.get(category, 0.75)

def import_findings():
    """Import findings from findings.jsonl into database"""
    if not FINDINGS_FILE.exists():
        print(f"❌ Findings file not found: {FINDINGS_FILE}")
        return
    
    am = AssetManager()
    imported_count = 0
    skipped_count = 0

    with FINDINGS_FILE.open('r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                finding = json.loads(line.strip())

                # Extract finding data
                target_url = finding.get("target", "")
                if not target_url:
                    skipped_count += 1
                    continue
                vuln_type = finding.get("category", "Unknown")
                param = finding.get("param", "")
                payload = finding.get("payload", "")
                evidence = finding.get("evidence", "")
                severity = map_severity(finding.get("severity", "medium"))
                confidence = map_confidence(vuln_type)
                ts = finding.get("ts")
                try:
                    discovered_at = datetime.fromisoformat(ts) if ts else datetime.now()
                except Exception:
                    discovered_at = datetime.now()

                # Ensure asset exists / get id
                with sqlite3.connect(DB_PATH) as db:
                    asset_id = get_asset_id_by_url(db, target_url)
                if not asset_id:
                    try:
                        from urllib.parse import urlparse
                        host = (urlparse(target_url).netloc or '')
                    except Exception:
                        host = ''
                    asset_id = am.add_asset(target_url, host, 'importer')
                    if not asset_id:
                        print(f"⚠️  Line {line_num}: Could not create asset for URL {target_url}")
                        skipped_count += 1
                        continue

                vf = VulnerabilityFinding(
                    url=target_url,
                    vuln_type=str(vuln_type).upper(),
                    severity=str(severity).capitalize(),
                    confidence=float(confidence),
                    payload=str(payload or ''),
                    evidence=str(evidence or ''),
                    discovered_at=discovered_at,
                    affected_parameter=str(param or ''),
                )
                am.add_vulnerability_finding(vf, asset_id)
                imported_count += 1

            except json.JSONDecodeError:
                print(f"❌ Line {line_num}: Invalid JSON")
                continue
            except Exception as e:
                print(f"❌ Line {line_num}: Error processing finding: {e}")
                continue

    print(f"✅ Import complete:")
    print(f"   📥 Imported: {imported_count} findings")
    print(f"   ⏭️  Skipped: {skipped_count} findings")

if __name__ == "__main__":
    import_findings()
