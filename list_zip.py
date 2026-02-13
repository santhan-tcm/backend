import zipfile
import os

zip_path = r'c:\Users\HP\Desktop\iso20022 Validator\backend\xsds\pacs.zip'
if os.path.exists(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for name in zf.namelist():
            print(name)
else:
    print("ZIP not found")
