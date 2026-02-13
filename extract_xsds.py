import os
import zipfile

xsd_root = r'C:\Users\HP\Desktop\iso20022 Validator\backend\xsds'
extracted_dir = os.path.join(xsd_root, 'extracted')
log_file = os.path.join(xsd_root, 'extraction_log.txt')

def log(msg):
    with open(log_file, 'a') as f:
        f.write(msg + '\n')
    print(msg)

if os.path.exists(log_file):
    os.remove(log_file)

if not os.path.exists(extracted_dir):
    os.makedirs(extracted_dir)

log(f"Scanning for zip files in {xsd_root}...")

for filename in os.listdir(xsd_root):
    if filename.endswith('.zip'):
        zip_path = os.path.join(xsd_root, filename)
        log(f"Extracting {filename}...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member.endswith('.xsd'):
                        basename = os.path.basename(member)
                        if basename:
                            target_path = os.path.join(extracted_dir, basename)
                            with zip_ref.open(member) as source, open(target_path, 'wb') as target:
                                target.write(source.read())
                log(f"  Done extracting {filename}")
        except Exception as e:
            log(f"  Error extracting {filename}: {str(e)}")

log("Extraction complete.")
