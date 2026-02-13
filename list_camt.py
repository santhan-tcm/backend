import zipfile
import os

zip_path = os.path.join('xsds', 'camt.zip')
if os.path.exists(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as z:
        with open('camt_contents.txt', 'w') as f:
            f.write('\n'.join(z.namelist()))
    print("Success")
else:
    print(f"File not found: {zip_path}")
