
import os
import zipfile
import traceback

LOG_FILE = r"c:\Users\HP\Desktop\iso20022 Validator\backend\extract_log.txt"
SOURCE_DIR = r"c:\Users\HP\Desktop\iso20022 Validator\backend\xsds"
TARGET_DIR = r"c:\Users\HP\Desktop\iso20022 Validator\backend\xsds\extracted"

with open(LOG_FILE, "w") as f:
    f.write("Log started\n")
    try:
        f.write(f"Source: {SOURCE_DIR}\n")
        f.write(f"Target: {TARGET_DIR}\n")
        
        if not os.path.exists(TARGET_DIR):
            os.makedirs(TARGET_DIR)
            f.write("Created target dir\n")
        
        files = os.listdir(SOURCE_DIR)
        f.write(f"Files in source: {files}\n")
        
        for filename in files:
            if filename.endswith(".zip"):
                f.write(f"Processing {filename}...\n")
                file_path = os.path.join(SOURCE_DIR, filename)
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        f.write(f"Zip content: {zip_ref.namelist()}\n")
                        zip_ref.extractall(TARGET_DIR)
                        f.write(f"Extracted {filename}\n")
                except Exception as e:
                    f.write(f"Error {filename}: {str(e)}\n")
                    f.write(traceback.format_exc() + "\n")
        f.write("Done\n")
    except Exception as e:
        f.write(f"Global error: {str(e)}\n")
        f.write(traceback.format_exc() + "\n")
