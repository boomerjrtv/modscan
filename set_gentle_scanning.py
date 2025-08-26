#!/usr/bin/env python3
"""
Configure ModScan for gentle scanning to avoid overwhelming targets like DVWA
"""

import os

print("🔧 Configuring ModScan for gentle scanning...")

# Set environment variables for gentle scanning
gentle_config = {
    'MODSCAN_MAX_CONCURRENCY': '5',        # Reduce from 1500 to 5 concurrent requests
    'MODSCAN_TIMEOUT': '15',               # Longer timeout for slower responses  
    'MODSCAN_THREADS': '3',                # Reduce from 150 to 3 threads
    'MODSCAN_WORDLIST_LIMIT': '1000',      # Reduce from 120k to 1k paths
    'MODSCAN_DELAY_MS': '500',             # Add 500ms delay between requests
    'MODSCAN_SKIP_LARGE_WORDLISTS': '1',   # Skip massive wordlists
    'MODSCAN_GENTLE_MODE': '1'             # Enable gentle mode flag
}

for key, value in gentle_config.items():
    os.environ[key] = value
    print(f"  {key}={value}")

print("\n✅ Gentle scanning configured!")
print("Restart the engines for changes to take effect:")
print("  sudo pkill -f engine.py")
print("  source .venv/bin/activate && python engine.py &")
print("\nThis will:")
print("  • Reduce concurrent requests from 1500 → 5")
print("  • Reduce discovery threads from 150 → 3") 
print("  • Limit wordlists from 120k+ → 1k paths")
print("  • Add 500ms delays between requests")
print("  • Skip massive SecLists to avoid overwhelming targets")