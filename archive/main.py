import subprocess
import os
import signal
import sys
import time

# The directory where the scripts are located
APP_DIR = os.path.dirname(os.path.abspath(__file__))

DASHBOARD_CMD = [sys.executable, os.path.join(APP_DIR, "dashboard.py")]
ENGINE_CMD = [sys.executable, os.path.join(APP_DIR, "engine.py")]

def find_pids(cmd):
    """Find PIDs of running processes matching the command."""
    pids = []
    try:
        # Use pgrep to find the processes
        pgrep_cmd = ["pgrep", "-f", ' '.join(cmd)]
        output = subprocess.check_output(pgrep_cmd).decode().strip()
        if output:
            pids = [int(pid) for pid in output.splitlines()]
    except subprocess.CalledProcessError:
        # pgrep returns non-zero exit status if no process is found
        pass
    except FileNotFoundError:
        print("Warning: pgrep not found. Process management might not be reliable.")
    return pids

def stop():
    """Stops the dashboard and engine services."""
    print("Stopping services...")
    for cmd in [DASHBOARD_CMD, ENGINE_CMD]:
        pids = find_pids(cmd)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
                print(f"Killed process {pid} for {' '.join(cmd)}")
            except ProcessLookupError:
                pass # Process already gone
            except Exception as e:
                print(f"Error killing process {pid}: {e}")
    print("Services stopped.")

def start():
    """Starts the dashboard and engine services."""
    print("Starting services...")
    print("Starting dashboard...")
    subprocess.Popen(DASHBOARD_CMD)
    time.sleep(2) # Give the dashboard a moment to start
    print("Starting engine...")
    subprocess.Popen(ENGINE_CMD)
    print("Services started.")
    print(f"Dashboard should be available at http://localhost:8000")


def restart():
    """Restarts the services."""
    stop()
    time.sleep(1)
    start()

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ["start", "stop", "restart"]:
        print("Usage: python3 main.py {start|stop|restart}")
        sys.exit(1)

    action = sys.argv[1]

    if action == "start":
        start()
    elif action == "stop":
        stop()
    elif action == "restart":
        restart()
