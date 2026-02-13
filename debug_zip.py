import os
import zipfile

xsd_root = r'C:\Users\HP\Desktop\iso20022 Validator\backend\xsds'
print(f"Directory: {xsd_root}")
for f in os.listdir(xsd_root):
    if f.endswith('.zip'):
        print(f"Zip: {f}")
        try:
            with zipfile.ZipFile(os.path.join(xsd_root, f), 'r') as z:
                print(f"  Files: {z.namelist()[:5]}... (total {len(z.namelist())})")
        except Exception as e:
            print(f"  Error: {e}")
