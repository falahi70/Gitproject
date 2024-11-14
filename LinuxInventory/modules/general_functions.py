import json
import sys
import datetime
import ipaddress
import uuid
import csv
import os
import shutil
import pandas as pd
import codecs
import re
import subprocess

def load_config():
    try:
        config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config = json.load(config_handle)
        config_handle.close()
        return config
    except Exception as e:
        print(f"[-] Failed to load config file.\n[Err] {e}")
        sys.exit(0)

def current_time(filename=False):
    if not filename:
        return str(datetime.datetime.now())[:19]
    else:
        c_time = str(datetime.datetime.now())[:19]
        c_time = c_time.replace(" ", "")
        c_time = c_time.replace("-", "")
        c_time = c_time.replace(":", "")
        return c_time

def ip2long(str_ipaddress):
    return int(ipaddress.ip_address(str_ipaddress))

def long2ip(int_ipaddress):
    return str(ipaddress.ip_address(int(int_ipaddress)))

def generate_new_GUID():
    uuidFour = uuid.uuid4()
    uuidFour = str(uuidFour).replace("{", "").replace("}", "")
    return uuidFour

def get_csv_headers(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as csv_file:
        csv_reader = csv.reader(csv_file)
        headers = next(csv_reader)
    return headers

def rename_directory_with_timestamp(directory_path):

    folder_name = 'InventoryData'
    oldfolder = directory_path+"/"+folder_name
    current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    new_folder_name = f"{directory_path}/{folder_name}_{current_time}"
    
    try:
        os.rename(oldfolder,new_folder_name)
        print(f"{new_folder_name}")
    except Exception as e:
        print(f"{e}")


def copyprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.zip')==True:
                shutil.copy(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def cutprocess(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.zip')==True:
                shutil.move(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def cutprocessFile(file, newpath):
    try:
       shutil.move(file,newpath)
       print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')
        
def cutprocessfortxt(oldpath,newpath):
    try:
        for file in os.listdir(oldpath):
            if file.endswith('.txt')==True:
                shutil.move(f'{oldpath}/{file}',newpath)
                print(f'ok')
    except FileNotFoundError as e:
        print(f'error:{e}')
    except IOError as e:
        print(f'error:{e}')

def removeDuplicate(group_name,csv):
    try:
        csv_file_path = csv
        df = pd.read_csv(csv_file_path,low_memory=False)    
        if group_name in ("product", "bios", "diskDrive", "group", "logcalDisk", "printer",
                            "printerConfiguration"):
            if 'caption' in (df.columns):
                df.drop_duplicates(subset=['hostname', 'caption'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)
        elif group_name in ("bootConfiguration", "service", "startupCommand", "systemDriver", "userAccount"):
            if 'name' in (df.columns):    
                df.drop_duplicates(subset=['hostname', 'name'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)
        elif group_name in ("networkAdapter"):
            if 'interfaceindex'  in (df.columns):   
                df.drop_duplicates(subset=['hostname', 'interfaceindex'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapterConfiguration"):
            if 'interfaceindex'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'interfaceindex'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("physicalMemory"):
            if 'devicelocator'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'devicelocator'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("quickFixEngineering"):
            if 'hotfixid'  in (df.columns):
                df.drop_duplicates(subset=['hostname', 'hotfixid'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("processor", "usbController"):
            if 'deviceid'  in (df.columns):    
                df.drop_duplicates(subset=['hostname', 'deviceid'], keep='last', inplace = True)
                df.to_csv(csv_file_path, index=False)

        else:
            df.drop_duplicates(subset=['hostname'], keep='last', inplace = True)
            df.to_csv(csv_file_path, index=False)

    except OSError as e:
        print(f'Error deleting {csv}: {e}')

def removeNullRecod(group_name,csv):
    try:
        csv_file_path = csv
        df = pd.read_csv(csv_file_path,low_memory=False)

        if group_name in ("product", "bios", "diskDrive", "group", "logcalDisk", "printer",
                            "printerConfiguration"):
            if 'caption' in (df.columns):
                df.dropna(subset=['hostname', 'caption'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("bootConfiguration", "service", "startupCommand", "systemDriver", "userAccount"):
            if 'name' in (df.columns):
                df.dropna(subset=['hostname', 'name'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapter"):
            if 'interfaceindex' in (df.columns):   
                df.dropna(subset=['hostname', 'interfaceindex'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("networkAdapterConfiguration"):
            if 'interfaceindex' in (df.columns):
                df.dropna(subset=['hostname', 'interfaceindex'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("physicalMemory"):
            if 'devicelocator' in (df.columns):    
                df.dropna(subset=['hostname', 'devicelocator'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("quickFixEngineering"):
            if 'hotfixid' in (df.columns):     
                df.dropna(subset=['hostname', 'hotfixid'], how='all')
                df.to_csv(csv_file_path, index=False)

        elif group_name in ("processor", "usbController"):
            if 'deviceid' in (df.columns):    
                df.dropna(subset=['hostname', 'deviceid'], how='all')
                df.to_csv(csv_file_path, index=False)

        else:
            df.dropna(subset=['hostname'], how='all')
            df.to_csv(csv_file_path, index=False)

    except OSError as e:
        print(f'Error deleting {csv}: {e}')
        
def remove_non_matching_columns(csv_filename, table_column_names):
    try:
        # بررسی وجود فایل CSV
        with open(csv_filename):
            pass
    except FileNotFoundError:
        print(f"Error: File '{csv_filename}' not found!")
        return

    try:
        # خواندن هدرهای فایل CSV
        csv_headers = pd.read_csv(csv_filename, nrows=1).columns.tolist()
    except pd.errors.EmptyDataError:
        print(f"Error: No header found in '{csv_filename}'!")
        return

    # بررسی تطابق هدرهای فایل CSV با نام‌های ستون‌های جدول
    non_matching_columns = [col for col in csv_headers if col not in table_column_names]

    # اگر هدرهایی وجود داشته باشند که در لیست مشخص نیستند، حذف می‌شوند
    if non_matching_columns:
        try:
            # حذف هدرهای غیرمطابق
            df_filtered = pd.read_csv(csv_filename, low_memory=False).drop(columns=non_matching_columns)

            # ذخیره DataFrame به فایل CSV
            df_filtered.to_csv(csv_filename, index=False)
            print("Non-matching columns removed successfully.")
        except Exception as e:
            print(f"Error occurred while removing non-matching columns: {e}")
    else:
        print("No non-matching columns found.")

def deleteInventoryFolder(current_directory, directory_to_delete):
    current_directory = current_directory
    directory_to_delete = directory_to_delete
    path_to_delete = os.path.join(current_directory, directory_to_delete)
    if os.path.exists(path_to_delete):
        try:
            shutil.rmtree(path_to_delete)
            print(f'پوشه "{directory_to_delete}"Delete Success')
        except Exception as e:
            print(f'خطا در حذف پوشه: {e}')
    else:
        print(f'پوشه "{directory_to_delete}" No Folder')

def replace_escape_characters(json_string):
    # جایگزینی همه کاراکترهای غیرقابل چاپ و کنترلی در محدوده مشخص<200c>شده
    json_string = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7f-\x9f]', '', json_string)

    # جایگزینی کاراکترهای خاص
    problematic_characters = ["\xEF", "\xBF"]

    for char in problematic_characters:
        json_string = json_string.replace(char, '')

    # حذف فاصله<200c>های اضافی از انتهای رشته<200c>ها
    json_string = re.sub(r'(?<=\S)\s+$', '', json_string, flags=re.MULTILINE)

    return json_string

def read_file_with_encodings(file_path):
    with open(file_path, 'rb') as f:
        raw = f.read(4)  # خواندن چند بایت اول برای بررسی BOM

    if raw.startswith(codecs.BOM_UTF16_LE):
        encoding_to_use = 'utf-16le'
    elif raw.startswith(codecs.BOM_UTF16_BE):
        encoding_to_use = 'utf-16be'
    elif raw.startswith(codecs.BOM_UTF8):
        encoding_to_use = 'utf-8-sig'
    else:
        encoding_to_use = 'utf-8'

    try:
        with open(file_path, 'r', encoding=encoding_to_use) as file:
            return file.read(), encoding_to_use
    except UnicodeDecodeError as e:
        raise UnicodeDecodeError(f"Could not read {file_path} with the encoding {encoding_to_use}: {e}")

def process_json_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".txt") and len(filename)>0:
            file_path = os.path.join(directory, filename)

            if os.path.getsize(file_path) == 0:
                print(f"Skipping {file_path} because the file size is 0.")
                try:
                    os.remove(file_path)
                    print(f'فایل "{file_path}"Delete Success')
                except Exception as e:
                    print(f'خطا در حذف فایل: {e}')
                continue

            try:
                # تلاش برای خواندن فایل
                json_data, encoding_used = read_file_with_encodings(file_path)
                print(f"Successfully read {file_path} with encoding {encoding_used}")

                # جایگزینی کاراکترهای escape و حذف فاصله<200c>های اضافی
                json_data = replace_escape_characters(json_data)

                # دوباره ذخیره<200c>سازی JSON به فایل
                with open(file_path, 'w', encoding=encoding_used) as file:
                    file.write(json_data)

            except UnicodeDecodeError as e:
                print(f"Error processing file {file_path}: {e}")

# تابع پردازش فایل JSON
def process_json_file(file_path):
    if os.path.getsize(file_path) == 0:
        print(f"Skipping {file_path} because the file size is 0.")
        try:
            os.remove(file_path)
            print(f'فایل "{file_path}"Delete Success')
        except Exception as e:
            print(f'خطا در حذف فایل: {e}')
	
    try:
        # خواندن فایل با کدک مناسب
        json_data, encoding_used = read_file_with_encodings(file_path)
        print(f"Successfully read {file_path} with encoding {encoding_used}")

        # جایگزینی کاراکترهای escape و حذف فاصله<200c>های اضافی
        json_data = replace_escape_characters(json_data)

        if json_data.startswith('\ufeff'):
            json_data = json_data.lstrip('\ufeff')

        try:
            json_parsed = json.loads(json_data)
            return json_parsed
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON from {file_path}: {e}")
            return None

    except UnicodeDecodeError as e:
        print(f"Error processing file {file_path}: {e}")
        return None
# تابع بررسی کدگذاری فایل
def detect_encoding_with_Linux(file_path):
    result = subprocess.run(['file', '-i', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        output = result.stdout.strip()
        encoding_info = output.split('charset=')[-1]
        print(f"Detected encoding: {encoding_info}")
        return encoding_info
    else:
        print(f"Error detecting encoding: {result.stderr}")
        return None

def convert_to_utf16_le(input_file_path, output_file_path, input_encoding=None):
    try:
        if input_encoding == 'utf-8':
            input_encoding = 'utf-8-sig'

        # خواندن فایل ورودی با کدگذاری مشخص‌شده
        with open(input_file_path, 'r', encoding=input_encoding) as infile:
            content = infile.read()

        # حذف BOM اگر وجود داشته باشد
        if content.startswith('\ufeff'):
            content = content[1:]

        # نوشتن محتوای فایل به کدگذاری utf-16-le در فایل موقت
        with open(output_file_path, 'w', encoding='utf-16-le') as outfile:
            outfile.write(content)

        print(f"File converted to UTF-16-LE successfully and saved to {output_file_path}")
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        print(f"Error during encoding conversion: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def lower_keys_in_dict(d):
    if isinstance(d, dict):
        return {key.lower(): value for key, value in d.items()}
    return d

# تابع برای تبدیل کلیدهای یک دسته به حروف کوچک
def lower_keys_in_category(json_data, category):
    if category in json_data:
        # بررسی اینکه آیا دسته یک دیکشنری است یا لیست
        if isinstance(json_data[category], dict):
            json_data[category] = lower_keys_in_dict(json_data[category])
        elif isinstance(json_data[category], list):
            # اگر دسته یک لیست است، کلیدهای هر دیکشنری داخل لیست را به حروف کوچک تبدیل می‌کنیم
            json_data[category] = [lower_keys_in_dict(item) for item in json_data[category]]
        else:
            print(f"Category '{category}' is neither a dictionary nor a list of dictionaries.")
    else:
        print(f"Category '{category}' not found in the JSON file.")
    return json_data
