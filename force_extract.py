import os
import zipfile

with open('script_start.txt', 'w') as f:
    f.write('Started\n')

try:
    xsd_root = r'C:\Users\HP\Desktop\iso20022 Validator\backend\xsds'
    extracted_dir = os.path.join(xsd_root, 'extracted')
    
    if not os.path.exists(extracted_dir):
        os.makedirs(extracted_dir)
        
    for filename in os.listdir(xsd_root):
        if filename.endswith('.zip'):
            zip_path = os.path.join(xsd_root, filename)
            with zipfile.ZipFile(zip_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.xsd'):
                        z.extract(name, extracted_dir)
    
    with open('script_end.txt', 'w') as f:
        f.write('Finished\n')
except Exception as e:
    with open('script_error.txt', 'w') as f:
        f.write(str(e) + '\n')
