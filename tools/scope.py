#!/usr/bin/env python3
"""
Simple CLI to manage scan scope without hardcoding.
Usage:
  python3 tools/scope.py add 192.168.1.42
  python3 tools/scope.py list
  python3 tools/scope.py delete <id>
"""

import sys
from asset_manager import AssetManager

def main():
    am = AssetManager()
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == 'add' and len(sys.argv) == 3:
        domain = sys.argv[2]
        rid = am.add_scope_target(domain)
        if rid:
            print(f"Added: {domain} (id={rid})")
        else:
            print("Failed to add scope target.")
    elif cmd == 'list':
        rows = am.get_scope_targets()
        if not rows:
            print("No scope targets.")
        else:
            for tid, dom, wildcard in rows:
                print(f"{tid}\t{dom}\t{'*' if wildcard else ''}")
    elif cmd == 'delete' and len(sys.argv) == 3:
        tid = int(sys.argv[2])
        ok = am.delete_scope_target(tid)
        print("Removed" if ok else "Not found")
    else:
        print(__doc__)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

