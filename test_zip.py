
import zipfile
import os

zip_path = r"c:\Users\HP\Desktop\iso20022 Validator\backend\xsds\pacs.zip"
out_path = r"c:\Users\HP\Desktop\iso20022 Validator\backend\zip_contents.txt"

try:
    with zipfile.ZipFile(zip_path, 'r') as z:
        with open(out_path, 'w') as f:
            f.write("\n".join(z.namelist()))
except Exception as e:
    with open(out_path, 'w') as f:
        f.write(str(e))
