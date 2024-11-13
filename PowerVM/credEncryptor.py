from cryptography.fernet import Fernet
import psycopg2
import datetime
from optparse import OptionParser
import sys
import requests
import json
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


parser = OptionParser()
parser.add_option("-n", "--credname", dest="credname",
                  help="Enter Your Credential Name.", default=False)

parser.add_option("-u", "--username", dest="username",
                  help="Enter Your Username.", default=False)

parser.add_option("-p", "--password", dest="password",
                  help="Enter Your Password.", default=False)

parser.add_option("-r", "--resource", dest="resource",
                  help="Enter Resource Key.", default=False)

parser.add_option("-a", "--action", dest="action",
                  help="Enter Your Password.", default=False)
(options, args) = parser.parse_args()


# Validating desired action for managing credential
if options.action:
    if "c" in str(options.action)[0].lower():
        action = "create"
    elif "d" in str(options.action)[0].lower():
        action = "delete"
    elif "m" in str(options.action)[0].lower():
        action = "modify"
    else:
        action = "None"
else:
    sys.exit(0)

key = "XuJdbHbZy5Tr66D5y4EwR-jXt8iXFmiQTBAe7CVaojc=".encode("utf-8")
cipher_suite = Fernet(key)

def current_time():
    c_time = str(datetime.datetime.now())
    return c_time[:19]


config = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
config = json.load(config)
CORESOLUTION_IP = config["coreInspectIpAddress"]
CORESOLUTION_USERNAME = config["coreInspectUsername"]
CORESOLUTION_PASSWORD = config["coreInspectPassword"]
CORESOLUTION_SCHEMA = config["coreInspectConnectionSchema"]
HTTPUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0'
def Get_JWT(Username=CORESOLUTION_USERNAME, Password=CORESOLUTION_PASSWORD, ipAddrses=CORESOLUTION_IP):
    def authorize(Username, Password):
        headers = {
            'Host': f'{ipAddrses}:8080',
            'User-Agent': HTTPUserAgent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '72',
            'Origin': f'{CORESOLUTION_SCHEMA}://{ipAddrses}',
            'Connection': 'close',
            'Referer': f'{CORESOLUTION_SCHEMA}://{ipAddrses}/',
        }
        data = rf'grant_type=password&client_id=ro&username={Username}&password={Password}'
        response = requests.post(f'{CORESOLUTION_SCHEMA}://{ipAddrses}:8080/connect/token', headers=headers, data=data, verify=False)
        jwt_token_response = json.loads(response.text)
        # print(jwt_token_response)
        jwt_token = jwt_token_response["access_token"]
        token_status = response.status_code
        return jwt_token, token_status, jwt_token_response

    jwt_token, token_status, responseStatus = authorize(Username, Password)
    try:
        if "2" not in str(token_status):
            print("Wrong Credential Provided")
        else:
            return jwt_token, token_status
    except:
        print(f"Token Status: {token_status}")
        print(f"Token Response: {responseStatus}")
        print("Wrong Credential Provided")

def dbconnect():
    conn = psycopg2.connect(
        host="localhost",
        database="CoreInspect",
        user="postgres",
        password="1234rewq!@#$REWQ")

    ps_cursor = conn.cursor()
    return conn, ps_cursor

def encrypt(password):
    password = password.encode("utf-8")
    encoded_text = cipher_suite.encrypt(password)
    return encoded_text.decode("utf-8")

def decrypt(password):
    password = password.encode("utf-8")
    decoded_text = cipher_suite.decrypt(password)
    return decoded_text.decode("utf-8")

def check_db_duplicate(credentialName):
    conn, curser = dbconnect()
    sql = f"Select count(name) from \"asset_inventory\".\"clixml\" Where name = '{credentialName}'"
    try:
        curser.execute(sql)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(0)
    credentialCount = curser.fetchall()
    credentialCount = credentialCount[0][0]
    if credentialCount > 0:
        print("Credential Name Is Already Available.")
        sys.exit(0)
    else:
        return False

def add_credential_db(credentialName, credentialUsernme, credentialPassword):
    check_db_duplicate(credentialName)

    conn, cursor = dbconnect()
    credential_string = f"{credentialUsernme} || {credentialPassword}"
    credential_string = encrypt(credential_string)
    sql = f"Insert Into \"asset_inventory\".\"clixml\" (name, path, string, createdtime) VALUES (%s,%s,%s,%s)"
    values = (credentialName, "-", credential_string, current_time())
    cursor.execute(sql, values)
    conn.commit()

def delete_credential_db(credentialName):
    conn, cursor = dbconnect()
    sql = f"Delete From \"asset_inventory\".\"clixml\" Where name = '{credentialName}'"
    cursor.execute(sql)
    conn.commit()

def modify_credential_db(credentialName, credentialUsernme, credentialPassword):
    conn, cursor = dbconnect()
    credential_string = f"{credentialUsernme} || {credentialPassword}"
    credential_string = encrypt(credential_string)
    print(credential_string)
    sql = f"Update \"asset_inventory\".\"clixml\" set string = '{credential_string}', createdtime = '{current_time()}' Where name = '{credentialName}'"
    print(sql)
    values = (credentialName, "-", credential_string, current_time())
    cursor.execute(sql)
    conn.commit()
    print("Credential Successfully Modified.")

def add_credential_coresolution(credentialName):
    jwt_token, token_status = Get_JWT()
    final_cpl = rf'{{"name":"{credentialName}","description":null,"username":"{credentialName}","password":"password","confirmPassword":"password","ssh":"","passPhrase":"","type":"Password","totalConnectionsCount":0,"totalDataSourcesCount":0,"isPasswordChanged":true}}'
    headers = {
        'Host': f'{CORESOLUTION_IP}:8081',
        'User-Agent': HTTPUserAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {jwt_token}',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Length': f'141',
        'Origin': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}',
        'Connection': 'close',
        'Referer': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}/',
    }

    response = requests.post(f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}:8081/rest/api/job/v4.0/Credentials',
                             headers=headers, data=final_cpl,
                             verify=False)
    if str(response.status_code) == "201":
        print("Credential Successfully Added To CoreDynamix.")
    else:
        print("Failed To Add Credential To CoreSolution")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

def delete_credential_coresolution(credentialName):
    jwt_token, token_status = Get_JWT()
    headers = {
        'Host': f'{CORESOLUTION_IP}:8081',
        'User-Agent': HTTPUserAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {jwt_token}',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}',
        'Connection': 'close',
        'Referer': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}/',
    }
    request_path = f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}:8081/rest/api/job/v4.0/Credentials/{credentialName}'
    response = requests.delete(request_path, headers=headers, verify=False)
    if str(response.status_code) == "200":
        print("Credential Successfully Deleted From CoreDynamix.")
    else:
        print("Failed To Delete Credential From CoreDynamix")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")

def delete_resource_type_coresolution(resourceKey):
    jwt_token, token_status = Get_JWT()
    headers = {
        'Host': f'{CORESOLUTION_IP}:8081',
        'User-Agent': HTTPUserAgent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': f'Bearer {jwt_token}',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}',
        'Connection': 'close',
        'Referer': f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}/',
    }
    request_path = f'{CORESOLUTION_SCHEMA}://{CORESOLUTION_IP}:8081/rest/api/resource/v4.0/Resources/{resourceKey}'
    response = requests.delete(request_path, headers=headers, verify=False)
    if str(response.status_code) == "200":
        print("Resource Successfully Deleted From CoreDynamix.")
    else:
        print("Failed To Delete Resource To CoreDynamix")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")


if action == "create":
    add_credential_db(options.credname, options.username, options.password)
    add_credential_coresolution(options.credname)

elif action == "modify":
    modify_credential_db(options.credname, options.username, options.password)

elif action == "delete":
    delete_credential_db(options.credname)
    delete_credential_coresolution(options.credname)
    delete_resource_type_coresolution(options.resource)
