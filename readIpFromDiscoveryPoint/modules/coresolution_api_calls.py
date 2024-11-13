import requests
import json
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
HTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0"
jwt_token = None
coresolution_ip = None
coresolution_schema = None
username = None
password = None


def get_jwt_token(Username, Password, ipAddrses, coresolution_schema="https"):
    def authorize(Username, Password):
        headers = {
            'Host': f'{ipAddrses}:8080',
            'User-Agent': HTTPUserAgent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '72',
            'Origin': f'{coresolution_schema}://{ipAddrses}',
            'Connection': 'close',
            'Referer': f'{coresolution_schema}://{ipAddrses}/',
        }
        data = rf'grant_type=password&client_id=ro&username={Username}&password={Password}'
        response = requests.post(f'{coresolution_schema}://{ipAddrses}:8080/connect/token', headers=headers, data=data, verify=False)
        try:
            jwt_token_response = json.loads(response.text)
            jwt_token = jwt_token_response["access_token"]
        except Exception as e:
            jwt_token_response = response.text
            jwt_token = "DoesNotExist"
            print(f"[-] Error On JWT Toen Fetch: {e}")
        token_status = response.status_code
        return jwt_token, token_status, jwt_token_response
    def Wrong_Credential():
        print("[-] Wrong Credential Has Been Provided.")
        sys.exit(0)

    jwt_token, token_status, responseStatus = authorize(Username, Password)
    try:
        if "2" not in str(token_status):
            Wrong_Credential()
        else:
            return jwt_token, token_status
    except:
        print(f"[-] Token Status: {token_status}")
        print(f"[-] Token Response: {responseStatus}")
        Wrong_Credential()

def create_new_job(coresolution_schema, coresolution_ip, jwt_token, cpl):

    headers = {
        'Host': f'{coresolution_ip}:8081',
        'User-Agent': HTTPUserAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {jwt_token}',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Length': '121',
        'Origin': f'{coresolution_schema}://{coresolution_ip}',
        'Connection': 'close',
        'Referer': f'{coresolution_schema}://{coresolution_ip}/',
    }

    sanitized_cpl = cpl.replace('"', r'\"')
    api_body = f'''{{"cpl":"{sanitized_cpl}","timeRange":null,"moduleName":"Resources","searchPoint":"ApplicationModule","runId":""}}'''
    # print(f"ABI Body:\n{api_body}")
    # print("---------------------------")
    api_response = requests.post(f'{coresolution_schema}://{coresolution_ip}:8081/rest/api/job/v4.0/Jobs',
                                 headers=headers,
                                 data=api_body,
                                 verify=False)
    parsed_api_response = api_response.json()
    try:
        job_id = parsed_api_response["values"]["id"]
        return job_id
    except Exception as e:
        print(f"[-] Failed To Create Job: {e}")
        print(f"[Err] {parsed_api_response}")
        sys.exit(0)

def watch_job_status(job_id):
    def get_job_status(job_id):
        headers = {
            'Host': f'{coresolution_ip}:8081',
            'User-Agent': HTTPUserAgent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': f'Bearer {jwt_token}',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': f'{coresolution_schema}://{coresolution_ip}',
            'Connection': 'close',
            'Referer': f'{coresolution_schema}://{coresolution_ip}/',
        }
        response = requests.get(
            f'{coresolution_schema}://{coresolution_ip}:8081/rest/api/job/v4.0/Jobs/{job_id}',
            headers=headers,
            verify=False)
        try:
            parsed_response = response.json()
            status = parsed_response["values"]["status"]
            return True, status

        except Exception as e:
            return False, str(response.content)

    while True:
        job_status_state, job_status = get_job_status(job_id)
        # print(f"[+] Job Status: {job_status}")
        if job_status_state:
            if job_status == "Completed":
                return True
            elif job_status == "Running" or job_status == "Queued":
                time.sleep(3)
            else:
                print(f"[-] Failed To Get Job Status.\n{job_status}")
                return -1

        else:
            print(f"[-] Failed To Get Job Status.\n{job_status}")
            return -1

def get_job_results(ipaddress, schema, job_id):
    jwt_token, token_status_code = get_jwt_token(username, password, ipaddress, coresolution_schema=schema)
    headers = {
        'Host': f'{coresolution_ip}:8081',
        'User-Agent': HTTPUserAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {jwt_token}',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': f'{coresolution_schema}://{coresolution_ip}',
        'Connection': 'close',
        'Referer': f'{coresolution_schema}://{coresolution_ip}/',
    }
    response = requests.get(
        f'{coresolution_schema}://{coresolution_ip}:8081/rest/api/job/v4.0/Jobs/{job_id}/Results?cpl=&pageIndex=1&pageSize=99999',
        headers=headers,
        verify=False,
        timeout=1000)
    try:
        parsed_response = response.json()
        status = parsed_response["results"]
        return True, status

    except Exception as e:
        return False, str(response.content)

def get_cpl_result(coresolution_schema_name, coresolution_ip_address, coresolution_username, coresolution_password, cpl):
    global jwt_token
    global coresolution_ip
    global coresolution_schema
    global username
    global password

    coresolution_ip = coresolution_ip_address
    coresolution_schema = coresolution_schema_name
    username = coresolution_username
    password = coresolution_password

    jwt_token, token_status_code = get_jwt_token(username, password, coresolution_ip,
                                                 coresolution_schema=coresolution_schema)

    job_id = create_new_job(coresolution_schema, coresolution_ip, jwt_token, cpl)
    print(f"[+] New Job Created: {job_id}")
    if watch_job_status(job_id):
        job_status, job_results = get_job_results(coresolution_ip, coresolution_schema, job_id)
        return job_results

# job_result = get_cpl_result(coresolution_schema, coresolution_ip, username, password, r'| search creator~"brco\\\\Reza.S"')
