import requests
from requests.auth import HTTPBasicAuth


def get_api_data(target_address, path, parameters, username, password):
    headers = {
        "Accept": "application/json",
        "Content-type": "application/json",
        "X-EMC-REST-CLIENT": "true"
    }

    response = requests.get(f'https://{target_address}{path}',
                            auth=HTTPBasicAuth(username, password),
                            verify=False,
                            allow_redirects=True,
                            headers=headers,
                            params=parameters)
    return response

def get_emc_general_data(target_iapddress, username, password):
    debug_data = {}
    api_path = "/api/types/basicSystemInfo/instances"
    parameters = {
        "fields": "name,model",
        "per_page": 2000
    }

    general_data = get_api_data(target_iapddress, api_path, parameters, username, password)
    response_statuscode = general_data.status_code
    response_data = general_data.json()

    # debug_data["ipaddress"] = target_iapddress
    # debug_data["username"] = username
    # debug_data["password"] = password
    # debug_data["response_statuscode"] = response_statuscode
    # debug_data["response_data"] = response_data
    # print(debug_data, flush=True)

    emc_name = response_data["entries"][0]["content"]["name"]
    emc_model = response_data["entries"][0]["content"]["model"]
    return emc_name, emc_model