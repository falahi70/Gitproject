import json
import shutil
import sys
from modules.startup import *
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi import Request
from flask import Flask, request, jsonify
from modules.general_functions import *
from modules.database_connections import *
import os
import zipfile
import base64
from pydantic import BaseModel
import time

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()

config = load_config()

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"]
)

user_password_validation = {
    "CoreInspectAgent": "C0r3!nsp3ct@gent_4567"
}

def validate_credential(username, password):
    user_list = list(user_password_validation.keys())
    if username not in user_list:
        return False
    if user_password_validation[username] == password:
        return True
    return False

@app.get("/openapi.json")
async def get_open_api_endpoint():
    return JSONResponse(get_openapi(title="FastAPI", version=1, routes=app.routes))

@app.get("/docs")
async def get_documentation():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

def insert_inventory_data(hostname, inventory_data):
    insert_queue = []

    config = load_config()
    db_queries = []

    for inventory_class_name, inventory_data in inventory_data.items():
        if not inventory_data:
            continue

        # db_columns = ["query", "createdtime", "scanid", "id", "name", "caption", "deviceid", "mediatype", "hostname",
        #               "scannedip", "osfamily", "scandigest"]

        db_columns = database_handle.get_column_names("asset_inventory", inventory_class_name)
        max_scanid = database_handle.get_max_scanid("asset_inventory", inventory_class_name, hostname)

        base_target = {
            "id": generate_new_GUID(),
            "createdtime": current_time(),
            "scannedip": "0",
            "hostname": hostname,
            "osfamily": "windows",
            "query": "N/A",
            "scanid": max_scanid,
            # "scanid": "1",
        }

        # Since some classes return result as a list, and some as one single JSON object
        # In this block of code I will make sure that either of the above situations will
        # get handled by converting both to list of JSONs (Even a single member list)
        wmi_results = []
        if "list" in str(type(inventory_data)):
            for item in inventory_data:
                wmi_results.append(item.copy())
        else:
            wmi_results.append(inventory_data.copy())

        # For each returned result, we will create a dictionary containing all the
        # required values for database rows.
        insert_queue.clear()

        for result in wmi_results:
            tmp_target = base_target.copy()
            for key, value in result.items():
                tmp_target[key.lower()] = value
            insert_queue.append(tmp_target.copy())

        for queue in insert_queue:
            base_query = f"insert into \"asset_inventory\".\"{inventory_class_name}\" ($cl$) VALUES($vl$);"
            for key, value in queue.items():
                # print(f"[key] {key} | [value] {value}")
                base_query = base_query.replace("$cl$", f'"{key}", $cl$')
                value = str(value).replace("'", "''")
                base_query = base_query.replace("$vl$", f"'{value}', $vl$")
            base_query = base_query.replace(", $cl$", "")
            base_query = base_query.replace(", $vl$", "")
            db_queries.append(base_query)

    for db_query in db_queries:
        print(db_query)
    print(f"[+] Recieved [{len(db_queries)}] Data.")
    # return db_queries

def hit_access_log(hostname, request_object, response="N/A"):
    request_host = request_object.client.host
    request_port = request_object.client.port
    request_endpoint = request_object.url
    request_hostname = hostname

    request_log = {
        "id": generate_new_GUID(),
        "request_host": request_host,
        "request_port": request_port,
        "request_endpoint": request_endpoint,
        "request_hostname": request_hostname,
        "created_time": current_time(),
        "response": response
    }

    database_handle.json2db("server_management", "access_logs", [request_log.copy()])

def process_file(filename):
    hostname = str(filename).replace(".zip", "")
    tmp_directory_name = f"{hostname}_{current_time(True)}"

    os.mkdir(tmp_directory_name)

    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall(tmp_directory_name)

    try:
        os.remove(filename)
    except Exception as e:
        print(f"[-] Failed to delete file [{filename}].")

    inventory_handle = open(f"{tmp_directory_name}/inventory_data.txt", "r", encoding="UTF-16", errors="ignore")
    # inventory_handle = open(filename, "r", encoding="UTF-16", errors="ignore")
    inventory_data_raw = inventory_handle.read()
    inventory_handle.close()
    inventory_data_raw = inventory_data_raw.strip()
    inventory_data_raw = inventory_data_raw.replace("\n", "")

    try:
        inventory_data = json.loads(inventory_data_raw)
    except Exception as e:
        print(f"[-] Failed To Convert To JSON.\n[Err] {e}")
        inventory_data = {}

    bulk_insert_categories = ["userAccount",
                              "group",
                              "groupUser",
                              "service",
                              "product"]
    bulk_insert_categories = list(inventory_data.keys())


    for category in bulk_insert_categories:
        max_scanid = database_handle.get_max_scanid("asset_inventory", category, hostname)
        if str(max_scanid).lower() == "none":
            max_scanid = 1
        else:
            max_scanid += 1
        category_data = inventory_data.get(category, [])
        del inventory_data[category]

        if "list" not in str(type(category_data)):
            category_data = [category_data]

        insert_data = []
        for data in category_data:
            if category == "product":
                if str(data["name"]).lower() == "none":
                    continue
            data["id"] = generate_new_GUID()
            data["createdtime"] = current_time()
            data["hostname"] = hostname
            data["scanid"] = max_scanid
            data["query"] = "N/A"
            data["scannedip"] = "0"
            data["osfamily"] = "windows"
            insert_data.append(data.copy())

        database_handle.json2bulkdb("asset_inventory", category, insert_data)

    try:
        shutil.rmtree(tmp_directory_name)
    except Exception as e:
        print(f"[-] Failed to delete directory [{tmp_directory_name}].")
    # os.remove(filename)

    # insert_inventory_data(hostname, inventory_data)

class CheckQueue(BaseModel):
    hostname: str
    credential: str
    hash: str

@app.post("/queue")
async def check_queue(request: Request,
                      post_data: CheckQueue):


    user_hostname = post_data.hostname
    file_hash = post_data.hash
    user_credentials = post_data.credential
    try:
        user_credentials = base64.b64decode(user_credentials).decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Error While reading credential.")

    user_username, user_password = user_credentials.split(":")
    if not validate_credential(user_username, user_password):
        hit_access_log(user_hostname, request, response="Invalid credential provided.")
        raise HTTPException(status_code=403, detail=f"Invalid credential provided.")
    hash_check_sql = f"select * from server_management.allowed_hash where md5_hash='{file_hash.lower()}' and enabled=1"
    print(hash_check_sql)
    fetched_data = database_handle.fetch_sql(hash_check_sql)
    if not fetched_data:
        raise HTTPException(status_code=403, detail=f"File hash is not valid.")


    user_job = database_handle.pick_job(user_hostname)
    print(f"[!] user_job: {user_job}")
    hostname_check_query = f"select * from asset_inventory.\"computerSystem\" where hostname='{user_hostname}' AND osfamily ='windows' AND createdtime > current_date - interval '4' day LIMIT 1"
    print(f"[!] Query: {hostname_check_query}")
    hostname_scanned = database_handle.fetch_sql(hostname_check_query)
    # print(f"[!] hostname_scanned: {hostname_scanned}")
    time.sleep(10)
    if user_job:
        user_job["queue_status"] = 1
        database_handle.json_update("server_management", "queue", user_job.copy())
        hit_access_log(user_hostname, request, response="true")
        return True
    elif not user_job and not hostname_scanned:
        hit_access_log(user_hostname, request, response="true")
        new_job_data = {
            "hostname": user_hostname,
            "job": "inventory",
            "queue_status": "1",
            "db_status": "0",
            "inventory_status": "0",
            "filename": "N/A",
            "created_time": current_time(),
            "finished_time": "0000-00-00 00:00:00"
        }
        # print(new_job_data)
        database_handle.json2db("server_management", "queue", [new_job_data.copy()], id_included=False)
        return True

    hit_access_log(user_hostname, request, response="false")
    return False


@app.post("/inventory")
def upload(request: Request,
           file: UploadFile = File(...),
           credential: str = Form(...)):


    hostname_uploaded_filename = str(file.filename).replace(".zip", "")
    user_job = database_handle.pick_job(hostname_uploaded_filename, inventory_endpoint=True)
    if not user_job:
        hit_access_log(hostname_uploaded_filename, request, response="No job defined.")
        raise HTTPException(status_code=403, detail=f"No job defined.")

    saved_filename = f'{hostname_uploaded_filename}_{current_time(True)}.zip'

    try:
        contents = file.file.read()
        with open(saved_filename, 'wb') as f:
            f.write(contents)
    except Exception:
        hit_access_log(hostname_uploaded_filename, request, response="Failed to process uploaded file.")
        raise HTTPException(status_code=503, detail=f"Failed to process uploaded file.")
    finally:
        file.file.close()

    if int(os.path.getsize(saved_filename)) > 500000:
        pass
        #hit_access_log(hostname_uploaded_filename, request, response="File size is bigger than the limitation.")
        #try:
        #    os.remove(saved_filename)
        #except Exception as e:
        #    print(f"[-] Failed to delete [{saved_filename}].")
        #raise HTTPException(status_code=403, detail=f"File size is bigger than the limitation.")

    try:
        user_credentials = base64.b64decode(credential).decode("utf-8")
    except Exception as e:
        hit_access_log(hostname_uploaded_filename, request, response="Error While reading credential.")
        raise HTTPException(status_code=403, detail=f"Error While reading credential.")
    user_username, user_password = user_credentials.split(":")
    if not validate_credential(user_username, user_password):
        hit_access_log(hostname_uploaded_filename, request, response="Invalid credential provided.")
        raise HTTPException(status_code=403, detail=f"Invalid credential provided.")


    user_job["inventory_status"] = "1"
    user_job["filename"] = saved_filename
    database_handle.json_update("server_management", "queue", user_job.copy())
    hit_access_log(hostname_uploaded_filename, request, response="true")
    return "true"
