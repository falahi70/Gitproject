import requests
import json
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import ssl



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def http_connection(address, timeout=5, port=None):
    https_scheme = "https"
    http_scheme = "http"
    if port == 80:
        https_scheme = "http"

    response_data = {
        "statuscode": False,
        "response": False,
        "response_size": False,
        "matched_pattern": False
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
    }
    try:
        response = requests.get(f"{https_scheme}://{address}", allow_redirects=True, verify=False, timeout=timeout, headers=headers)
        response_data["statuscode"] = response.status_code
        response_data["response"] = str(response.content.decode("utf-8"))
        response_data["response_size"] = len(str(response.content.decode("utf-8")))
    except Exception as e:
        try:
            response = requests.get(f"{http_scheme}://{address}", allow_redirects=True, timeout=timeout, headers=headers)
            response_data["statuscode"] = response.status_code
            response_data["response"] = str(response.content.decode("utf-8"))
            response_data["response_size"] = len(str(response.content.decode("utf-8")))
        except Exception as e:
            pass
    return response_data

def condition_checker(response_data, response_matcher, statuscode_matcher):
    condition_results = []
    match_count = 0

    if statuscode_matcher:
        match_count += 1
        if str(statuscode_matcher) == str(response_data["statuscode"]):
            condition_results.append(True)

    if response_matcher:
        match_count += 1
        if str(response_matcher) in str(response_data["response"]):
            condition_results.append(True)

    if False not in condition_results and len(condition_results) >= match_count:
        return True
    elif len(condition_results) == 0:
        return False
    return False



def scan_target(target_address, url, ports, response_matcher, statuscode_matcher, pattern_name, timeout):
    ports = ports.split(",")
    url = url.replace("$target$", target_address)
    for port in ports:
        target_url = url.replace("$port$", port)
        response_data = http_connection(target_url, timeout, port)
        condition_result = condition_checker(response_data, response_matcher, statuscode_matcher)
        if condition_result:
            response_data["matched_pattern"] = pattern_name[:-9]
            return condition_result, response_data
        else:
            return False, False

