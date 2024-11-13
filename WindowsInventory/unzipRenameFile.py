import os
import zipfile
import shutil

def unzipFile(path):
    directory_path = path
    
    extracted_base_directory = '/CoreInspect/agents/WindowsInventory/extracted'

   
    zip_files = [file for file in os.listdir(directory_path) if file.endswith('.zip')]

    
    for zip_file in zip_files:
        zip_file_path = os.path.join(directory_path, zip_file)

        
        extracted_directory = os.path.join(extracted_base_directory, os.path.splitext(zip_file)[0])
        os.makedirs(extracted_directory, exist_ok=True)

        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            
            zip_ref.extractall(extracted_directory)

        
        for root, dirs, files in os.walk(extracted_directory):
            for file_name in files:
                source_path = os.path.join(root, file_name)
                destination_path = os.path.join(extracted_base_directory, os.path.splitext(zip_file)[0] + '.txt')
                
                
                shutil.move(source_path, destination_path)

       
        for item in os.listdir(extracted_base_directory):
            item_path = os.path.join(extracted_base_directory, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)

        
        os.remove(zip_file_path)

    print(f"ok")

