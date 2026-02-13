import os
import zipfile
import shutil

xsd_root = r'C:\Users\HP\Desktop\iso20022 Validator\backend\xsds'
extracted_dir = os.path.join(xsd_root, 'extracted')

if not os.path.exists(extracted_dir):
    os.makedirs(extracted_dir)

# Clear it out if needed or just add to it
# shutil.rmtree(extracted_dir)
# os.makedirs(extracted_dir)

print(f"Extracting all zips into {extracted_dir}...")

for filename in os.listdir(xsd_root):
    if filename.endswith('.zip'):
        zip_path = os.path.join(xsd_root, filename)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if member.endswith('.xsd'):
                    # Flatten filename
                    clean_name = os.path.basename(member)
                    if clean_name:
                        target = os.path.join(extracted_dir, clean_name)
                        with zip_ref.open(member) as source, open(target, 'wb') as f:
                            f.write(source.read())

print("Finished!")
