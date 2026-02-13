
import os
import shutil
import time

files_to_remove = [
    "check_server.bat",
    "fix_deps.bat",
    "fix_deps_py.bat",
    "fix_log.txt",
    "fix_log_py.txt",
    "server_status.txt",
    "startup_error.txt",
    "cleanup.py"
]

dirs_to_remove = [
    "__pycache__",
    "app/__pycache__"
]

print("Starting cleanup...")

for d in dirs_to_remove:
    if os.path.exists(d):
        try:
            shutil.rmtree(d)
            print(f"Removed directory: {d}")
        except Exception as e:
            print(f"Failed to remove {d}: {e}")

for f in files_to_remove:
    if os.path.exists(f):
        try:
            os.remove(f)
            print(f"Removed file: {f}")
        except Exception as e:
            print(f"Failed to remove {f}: {e}")

print("Cleanup finished.")
