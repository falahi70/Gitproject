import requests
import json
import sys
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0"
jwt_token = None
coresolution_ip = None
coresolution_schema = None
username = None
password = None


class coresolution():
    def __init__(self, scheme, ipaddress, username, password):
        self.scheme = scheme
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.jwt_token = None
        self.useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"

    def get_post_header(self):
        post_header = {
            'Host': f'{self.ipaddress}:8081',
            'Connection': 'close',
            'Content-Length': '20',
            'Authorization': f'Bearer {self.jwt_token}',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': self.useragent,
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Origin': f'{self.scheme}://{self.ipaddress}'
        }
        return post_header

    def get_header(self):
        headers = {
            'Host': f'{self.ipaddress}:8081',
            'Connection': 'close',
            'Authorization': f'Bearer {self.jwt_token}',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': self.useragent,
            'Accept': '*/*',
            'Origin': f'{self.scheme}://{self.ipaddress}'
        }
        return headers

    def authenticate(self):
        def authorize():
            headers = {
                'Host': f'{self.ipaddress}:8080',
                'User-Agent': self.useragent,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': '72',
                'Origin': f'{self.scheme}://{self.ipaddress}',
                'Connection': 'close',
                'Referer': f'{self.scheme}://{self.ipaddress}/',
            }
            data = rf'grant_type=password&client_id=ro&username={self.username}&password={self.password}'
            response = requests.post(f'{self.scheme}://{self.ipaddress}:8080/connect/token', headers=headers,
                                     data=data, verify=False, timeout=60)
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

        jwt_token, token_status, responseStatus = authorize()
        try:
            if "2" not in str(token_status):
                Wrong_Credential()
            else:
                self.jwt_token = jwt_token
                return jwt_token, token_status
        except:
            print(f"[-] Token Status: {token_status}")
            print(f"[-] Token Response: {responseStatus}")
            Wrong_Credential()

    def get_credential(self, credentialname):
        def get_userid():
            request_uri = f'{self.scheme}://{self.ipaddress}:8080/connect/userinfo'
            response = requests.get(request_uri, headers=self.get_header(), verify=False)
            try:
                if response.status_code == 200:
                    return response.json()["sub"]
                else:
                    parsed_response = json.loads(response.text)
                    print(f"[-] Failed To Get UserID. | {parsed_response} | {response.status_code}")
                    return -1
            except Exception as e:
                print(f"[-] Failed To Get UserID. | {e}")
                return -1

        def get_special_token():
            credential_body = f'client_secret=secret&client_id=impersonation&scope=ReadCredential&grant_type=password&username={get_userid()}'
            post_header = {
                'Host': f'{self.ipaddress}:8080',
                'Connection': 'close',
                'Content-Length': '20',
                'Authorization': f'Basic aW1wZXJzb25hdGlvbjpzZWNyZXQ=',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.useragent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': '*/*',
                'Origin': f'{self.scheme}://{self.ipaddress}'
            }
            request_uri = f'{self.scheme}://{self.ipaddress}:8080/connect/token'
            response = requests.post(request_uri, headers=post_header, data=credential_body, verify=False, timeout=60)
            try:
                if response.status_code == 200:
                    return response.json()["access_token"]
                else:
                    parsed_response = json.loads(response.text)
                    print(f"[-] Failed To Get Special Token. | {parsed_response} | {response.status_code}")
                    return -1
            except Exception as e:
                print(f"[-] Failed To Get Special Token. | {e}")
                return -1

        # if not credentialname or len(credentialname) < 3:
        #     print(f"[-] Bad value passed as credential name: {credentialname}")
        #     return False

        headers = {
            'Host': f'{self.ipaddress}:8081',
            'Connection': 'close',
            'Authorization': f'Bearer {get_special_token()}',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': self.useragent,
            'Accept': '*/*',
            'Origin': f'{self.scheme}://{self.ipaddress}'
        }

        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/RawCredentials/{credentialname}'
        response = requests.get(request_uri, headers=headers, verify=False)
        try:
            if response.status_code == 200:
                return response.json()["values"]
            else:
                parsed_response = json.loads(response.text)
                print(f"[-] Failed To Get Credential. | {parsed_response} | {response.status_code}")
                return -1
        except Exception as e:
            print(f"[-] Failed To Get Credential. | {e}")
            return -1

    def create_scenario(self, scenario_name, scenario_severity, definition):
        resource_body = {
            "instanceKey": "SCEN",
            "resourceTypeName": "scenarioManagement",
            "values": [
                {
                    "fieldName": "name",
                    "value": scenario_name
                },
                {
                    "fieldName": "severity",
                    "value": scenario_severity
                },
                {
                    "fieldName": "definition",
                    "value": definition
                },
                {
                    "fieldName": "recommendedAction",
                    "value": ""
                }
            ],
            "attachments": [],
            "commentTexts": []
        }

        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/resource/v4.0/Resources'
        response = requests.post(request_uri, headers=self.get_post_header(), json=resource_body, verify=False, timeout=60)
        try:
            if response.status_code == 201:
                return True
            else:
                print("[-] Failed To Create Resource.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Create Resource: {e}")
            return -1

    def add_parser(self, parser_name, parser_body, monitor_template):
        resource_body = {
            "instanceKey": "PARS",
            "resourceTypeName": "parser",
            "values": [
                {
                    "fieldName": "name",
                    "value": parser_name
                },
                {
                    "fieldName": "monitorTemplate",
                    "value": monitor_template
                },
                {
                    "fieldName": "location",
                    "value": ""
                },
                {
                    "fieldName": "parserBody",
                    "value": ""
                },
                {
                    "fieldName": "description",
                    "value": parser_body
                },
                {
                    "fieldName": "owner",
                    "value": ""
                },
                {
                    "fieldName": "administrator",
                    "value": ""
                },
                {
                    "fieldName": "singleEmailAddress",
                    "value": ""
                }
            ],
            "attachments": [],
            "commentTexts": []
        }

        try:
            request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/resource/v4.0/Resources'
            response = requests.post(request_uri, headers=self.get_post_header(), json=resource_body, verify=False, timeout=60)
            if response.status_code == 201:
                return True
            else:
                print("[-] Failed To Create Resource.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Create Resource: {e}")
            return -1

    def add_monitor_template(self, monitortemplate_name):
        resource_body = {"instanceKey": "MONTMP", "resourceTypeName": "monitorTemplate",
                         "values": [{"fieldName": "name", "value": monitortemplate_name},
                                    {"fieldName": "description", "value": ""}, {"fieldName": "owner", "value": ""},
                                    {"fieldName": "administrator", "value": ""},
                                    {"fieldName": "singleEmailAddress", "value": ""}], "attachments": [],
                         "commentTexts": []}

        try:
            request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/resource/v4.0/Resources'
            response = requests.post(request_uri, headers=self.get_post_header(), json=resource_body, verify=False, timeout=60)
            if response.status_code == 201:
                response_parsed = response.json()
                return response_parsed["values"]["resources"][0]["key"]
            else:
                print("[-] Failed To Create Resource.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Create Resource: {e}")
            return -1

    def create_external_datasource(self, name=False, connection_name=False, credential_name=False, max_rows=False, database_host=False, database_name=False, database_tablename=False, timezone="Iran", datasource_object=False):
        if not datasource_object:
            request_body = {
              "name": name,
              "cpl": "",
              "connectionName": connection_name,
              "credentialName": credential_name,
              "description": None,
              "maxRows": max_rows,
              "type": "External",
              "timeZone": timezone,
              "properties": [
                {
                  "key": "Database",
                  "value": database_name
                },
                {
                  "key": "Host",
                  "value": database_host
                },
                {
                  "key": "Table",
                  "value": database_tablename
                }
              ]}
        else:
            request_body = datasource_object
        try:
            request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/DataSources'
            response = requests.post(request_uri, headers=self.get_post_header(), json=request_body, verify=False, timeout=60)
            if response.status_code == 201:
                response_parsed = response.json()
                return response_parsed
            else:
                print("[-] Failed To Create DataSource.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Create DataSource: {e}")
            return -1

    def fetch_datasource_details(self, datasource_name):
        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/DataSources/{datasource_name}'
        response = requests.get(request_uri, headers=self.get_header(), verify=False)
        try:
            if response.status_code == 200:
                return response.json()
            else:
                print("[-] Failed To Fetch Datasource Information.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Fetch Datasource Information: {e}")
            return -1

    def fetch_global_variables(self, variable_name):
        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/Variables/{variable_name}'
        response = requests.get(request_uri, headers=self.get_header(), verify=False)
        try:
            if response.status_code == 200:
                return response.json()["values"]["value"]
            else:
                print("[-] Failed To Fetch Datasource Information.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Fetch Datasource Information: {e}")
            return -1

    def change_global_variable(self, variable_name, data_type, new_value, description=""):
        json_body = {
                    "name": variable_name,
                    "description": description,
                    "isEncrypted": False,
                    "value": str(new_value),
                    "dataType": data_type,
                    "isValueChanged": True
                }
        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/Variables/{variable_name}'
        response = requests.put(request_uri, headers=self.get_post_header(), json=json_body, verify=False)
        if response.status_code == 204:
            return True
        else:
            return False

    def fetch_datasource_fields(self, datasource_name):
        request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/DataSources/{datasource_name}/Fields?pageSize=9999&cpl=&pageIndex=1'
        response = requests.get(request_uri, headers=self.get_header(), verify=False)
        try:
            if response.status_code == 200:
                return response.json()
            else:
                print("[-] Failed To Fetch Datasource Information.")
                parsed_response = json.loads(response.text)
                print(parsed_response)
                print(response.status_code)
                return -1
        except Exception as e:
            print(f"[-] Failed To Fetch Datasource Information: {e}")
            return -1

    def add_external_datasource_field(self, datasource_name, field_object):
        try:
            request_uri = f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/DataSources/{datasource_name}/Fields'
            response = requests.post(request_uri, headers=self.get_post_header(), json=field_object, verify=False, timeout=60)
            if response.status_code == 201:
                response_parsed = response.json()
                return response_parsed
            else:
                parsed_response = json.loads(response.text)
                print(f"[-] Failed To Create Field. | {parsed_response} | {response.status_code}")
                return parsed_response
        except Exception as e:
            print(f"[-] Failed To Create Field: {e}")
            return -1

    def add_new_ipcredential(self, resource_name_field, resource_ipaddress_field, resource_credential_field):
        create_resource_cpl = rf'{{"instanceKey":"SNMPDIS","resourceTypeName":"snmpDiscovery","values":[{{"fieldName":"name","value":"{resource_name_field}"}},{{"fieldName":"ipAddress","value":"{resource_ipaddress_field}"}},{{"fieldName":"credential","value":"{resource_credential_field}"}},{{"fieldName":"portNumber","value":""}},{{"fieldName":"connector","value":""}}],"attachments":[],"commentTexts":[]}}'
        response = requests.post(f'{self.scheme}://{self.ipaddress}:8081/rest/api/resource/v4.0/Resources',
                                 headers=self.get_post_header(), data=create_resource_cpl,
                                 verify=False, timeout=60)
        try:
            job_response = json.loads(response.text)
            return job_response, response.status_code
        except Exception as e:
            job_response_raw = response.text
            job_response = {"response": job_response_raw, "error": e}
            print(f"[-] Failed to create resource. {job_response}")
            return False


    def execute_cpl(self, cpl):
        def create_new_job(cpl):
            request_body = {"cpl": cpl,
                            "timeRange": None,
                            "moduleName": "Resources",
                            "searchPoint": "ApplicationModule",
                            "runId": ""}
            api_response = requests.post(f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/Jobs',
                                         headers=self.get_post_header(),
                                         json=request_body,
                                         verify=False, timeout=60)
            parsed_api_response = api_response.json()
            try:
                job_id = parsed_api_response["values"]["id"]
                return job_id
            except Exception as e:
                print(f"[-] Failed To Create Job: {e}")
                sys.exit(0)

        def watch_job_status(job_id):
            def get_job_status(job_id):
                response = requests.get(
                    f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/Jobs/{job_id}',
                    headers=self.get_header(),
                    verify=False)
                try:
                    parsed_response = response.json()
                    status = parsed_response["values"]["status"]
                    return True, status

                except Exception as e:
                    return False, str(response.content)

            while True:
                job_status_state, job_status = get_job_status(job_id)
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

        def get_job_results(job_id):
            response = requests.get(
                f'{self.scheme}://{self.ipaddress}:8081/rest/api/job/v4.0/Jobs/{job_id}/Results?cpl=&pageIndex=1&pageSize=99999',
                headers=self.get_header(),
                verify=False,
                timeout=1000)
            try:
                parsed_response = response.json()
                status = parsed_response["results"]
                return True, status

            except Exception as e:
                return False, str(response.content)


        job_id = create_new_job(cpl)
        if watch_job_status(job_id):
            job_status, job_results = get_job_results(job_id)
            if job_status:
                return job_results
            else:
                print("[-] Failed To Execute job.")
        else:
            print("[-] Failed To Execute job.")

    def get_monitortemplate_list(self):
        result = {}
        cpl_result = self.execute_cpl('| search resourceType="monitorTemplate" | fields name, key')
        for monitortemplate in cpl_result:
            monitortemplate_name = monitortemplate["name"]
            monitortemplate_key = monitortemplate["Key"]
            result[monitortemplate_name] = monitortemplate_key
        return result
