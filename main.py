#!/usr/bin/env python3
"""
🚀 MODSCAN MAIN LAUNCHER
Starts both dashboard and engine together
"""

import subprocess
import sys
print("!!!!!!!!!! MAIN.PY HAS BEEN RELOADED !!!!!!!!!!!")
import time
import signal
import os
from pathlib import Path

def cleanup_existing_processes():
    """Kill any existing dashboard or engine processes"""
    try:
        # Kill existing dashboard processes
        subprocess.run(['pkill', '-f', 'dashboard.py'], stderr=subprocess.DEVNULL)
        # Kill existing engine processes  
        subprocess.run(['pkill', '-f', 'engine.py'], stderr=subprocess.DEVNULL)
        time.sleep(2)
        print("✅ Cleaned up existing processes")
    except Exception as e:
        print(f"⚠️  Process cleanup warning: {e}")

def start_dashboard():
    """Start the dashboard service"""
    print("🚀 Starting Dashboard on http://localhost:8000...")
    dashboard_proc = subprocess.Popen([
        sys.executable, 'dashboard.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)  # Give dashboard time to start
    print("✅ Dashboard started")
    return dashboard_proc

def start_engine():
    """Start the scanning engine"""
    print("🚀 Starting Scanning Engine...")
    engine_proc = subprocess.Popen([
        sys.executable, 'engine.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)  # Give engine time to initialize
    print("✅ Engine started")
    return engine_proc

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n🛑 Shutting down ModScan...")
    cleanup_existing_processes()
    sys.exit(0)

def main():
    print("🎯 MODSCAN - Advanced Bug Bounty Platform")
    print("=" * 50)
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Clean up any existing processes
        cleanup_existing_processes()
        
        # Start services
        dashboard_proc = start_dashboard()
        engine_proc = start_engine()
        
        print("\n✅ MODSCAN FULLY OPERATIONAL!")
        print("🌐 Dashboard: http://localhost:8000")
        print("🔍 Engine: Running in background")
        print("🚀 Advanced Scanners: XBOW-crushing capabilities active")
        print("\nPress Ctrl+C to stop all services...")
        
        # Keep the main process alive and monitor subprocesses
        while True:
            time.sleep(5)
            
            # Check if dashboard is still running
            if dashboard_proc.poll() is not None:
                print("⚠️  Dashboard stopped, restarting...")
                dashboard_proc = start_dashboard()
            
            # Check if engine is still running
            if engine_proc.poll() is not None:
                print("⚠️  Engine stopped, restarting...")
                engine_proc = start_engine()
                
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        print(f"💥 Error: {e}")
        cleanup_existing_processes()
        sys.exit(1)

if __name__ == "__main__":
    main()
