
import os
import zipfile
import sys

# Hardcoded base for reliability in this specific environment
BASE_DIR = r"c:\Users\HP\Desktop\iso20022 Validator\backend"
SOURCE_DIR = os.path.join(BASE_DIR, "xsds")
TARGET_DIR = os.path.join(SOURCE_DIR, "extracted")
DONE_FILE = os.path.join(BASE_DIR, "extraction_done.txt")

print(f"Starting extraction to {TARGET_DIR}...", flush=True)

if not os.path.exists(TARGET_DIR):
    os.makedirs(TARGET_DIR, exist_ok=True)

try:
    for filename in os.listdir(SOURCE_DIR):
        if filename.endswith(".zip"):
            file_path = os.path.join(SOURCE_DIR, filename)
            print(f"Extracting {filename}...", flush=True)
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(TARGET_DIR)
            except Exception as e:
                print(f"Failed {filename}: {e}", flush=True)
                import traceback
                traceback.print_exc()

    with open(DONE_FILE, "w") as f:
        f.write("DONE")
    print("Everything done.", flush=True)

except Exception as e:
    print(f"Global error: {e}")
