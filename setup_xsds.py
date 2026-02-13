import os
import zipfile
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE_DIR, "xsds")
TARGET_DIR = os.path.join(SOURCE_DIR, "extracted")

print(f"Base Dir: {BASE_DIR}")
print(f"Source Dir: {SOURCE_DIR}")
print(f"Target Dir: {TARGET_DIR}")

if not os.path.exists(TARGET_DIR):
    try:
        os.makedirs(TARGET_DIR)
        print(f"Created directory: {TARGET_DIR}")
    except OSError as e:
        print(f"Error creating directory: {e}")

print(f"Extracting XSDs...", flush=True)

if not os.path.exists(SOURCE_DIR):
    print(f"Source directory does not exist!", flush=True)
    sys.exit(1)

count = 0
for filename in os.listdir(SOURCE_DIR):
    if filename.endswith(".zip"):
        file_path = os.path.join(SOURCE_DIR, filename)
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(TARGET_DIR)
                print(f"Extracted: {filename}", flush=True)
                count += 1
        except zipfile.BadZipFile:
            print(f"Error: {filename} is not a valid zip file", flush=True)
        except Exception as e:
            print(f"Failed to extract {filename}: {e}", flush=True)

print(f"Extraction complete. Extracted {count} files.", flush=True)
