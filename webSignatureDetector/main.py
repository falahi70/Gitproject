import argparse
import datetime
import sys
from modules.general_functions import *
from modules.scanner import *
from modules.database_connections import *
import concurrent.futures
import json
from multiprocessing.pool import ThreadPool
import ipaddress
from random import randint

start_time = datetime.datetime.now()
parser = argparse.ArgumentParser(description="Web Signature Detector")

# parser.add_argument("-sf", "--signaturefile",
#                     default="patterns.json",
#                     type=str,
#                     help='Location of file containing patterns.')
#
# parser.add_argument("-cf", "--configfile",
#                     default="appsettings.json",
#                     type=str,
#                     help='Location of appsettings file.')
#
# parser.add_argument("-a", "--address",
#                     default=False,
#                     help='Enter the IP Address that you want to test.')
#
# parser.add_argument("-al", "--address-list",
#                     default="ips.txt",
#                     help='Enter filename containing target in each line.')

parser.add_argument("-t", "--threads",
                    default=20,
                    type=int,
                    help='Enter thread count.')

parser.add_argument("-to", "--timeout",
                    default=5,
                    type=int,
                    help='Enter HTTP request timeout in seconds.')

options = parser.parse_args()

config_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
config = json.load(config_handle)
config_handle.close()

def current_time():
    return str(datetime.datetime.now())[:19]

def ip2long(strip):
    return int(ipaddress.ip_address(strip))
	
def get_rand_number():
    return randint(10000000, 99999999)


configs = load_config()
patterns = load_patterns()
# targets = get_target(options.address, options.address_list)

coresolution_handle = coresolution(config["coresolution_scheme"],
                                   config["coresolution_ipaddress"],
                                   config["coresolution_username"],
                                   config["coresolution_password"])
coresolution_handle.authenticate()
coresolution_targets = []
# targets = coresolution_handle.execute_cpl('| search    resourcetype = "networkNode" | fields    key, ipAddress | eval ipAddress := longtoip (ipAddress) | join  type := left @outer.ipAddress = @inner.ipaddress [ | datasource "connection_method_discovery_connectionMethod" | fields    ipaddress, discoveredConnectionMethod ] |   search      discoveredConnectionMethod in ("https")')
targets = coresolution_handle.execute_cpl('|snippet \"Web App Discovery Fetch IP\"')
for target in targets:
    # coresolution_targets.append(target["ipAddress"])
    coresolution_targets.append(target["ipaddress"])

coresolution_patterns = {}
tmp_patterns = coresolution_handle.execute_cpl('|snippet \"Fetch Web App Resource\"')
for pattern in tmp_patterns:
    pattern_name = pattern["name"]
    pattern_name = f"{pattern_name}_{get_rand_number()}"

    response_matcher = pattern["responseMatcher"]
    if str(response_matcher).lower() == "false":
        response_matcher = False

    statuscode_matcher = pattern["statusCodeMatcher"]
    if str(statuscode_matcher).lower() == "false":
        statuscode_matcher = False

    coresolution_patterns[pattern_name] = {}
    coresolution_patterns[pattern_name]["url"] = f'$target$:$port${pattern["uriQuery"]}'
    coresolution_patterns[pattern_name]["connection_port"] = pattern["connectionPort"]
    coresolution_patterns[pattern_name]["response_matcher"] = response_matcher
    coresolution_patterns[pattern_name]["statuscode_matcher"] = statuscode_matcher

def handle_target(target, patterns, timeout):
    for pattern in patterns:
        # print(f"[*] Checking For [{pattern}] Pattern [{target}].")
        condition_result, response_data = scan_target(target,
                                                      patterns[pattern]["url"],
                                                      patterns[pattern]["connection_port"],
                                                      patterns[pattern]["response_matcher"],
                                                      patterns[pattern]["statuscode_matcher"],
                                                      pattern,
                                                      timeout)
        if condition_result:
            return_result = {"createdtime": current_time(),
                             "scannedip": ip2long(target),
                             "service": pattern,
                             "response_matcher": patterns[pattern]["response_matcher"],
                             "statuscode_matcher": str(patterns[pattern]["statuscode_matcher"]),
                             "connection_port": patterns[pattern]["connection_port"]}
            print(f'[+] Matched Pattern: {response_data["matched_pattern"]} | IP Address: {target}')
            return return_result


if len(coresolution_targets) >= 8:
  thread_count = int(len(coresolution_targets)/8)
else:
  thread_count = 1
pool = ThreadPool(processes=thread_count)
results = []
while coresolution_targets:
    target = coresolution_targets.pop()
    results.append(pool.apply_async(handle_target, (target, coresolution_patterns, options.timeout,)))

pool.close()
pool.join()
total_results = [result.get() for result in results if str(result).lower() != "none"]

# while len(coresolution_targets) > 0:
#     target_queue = coresolution_targets[:thread_count]
#     del coresolution_targets[:thread_count]
#
#     thread_list = []
#     thread_results = []
#     append_threadresult = []
#
#     executor = concurrent.futures.ThreadPoolExecutor()
#     for target in target_queue:
#         thread_list.append(executor.submit(handle_target, target, coresolution_patterns, options.timeout))
#     thread_results = [thread_result.result() for thread_result in thread_list]
#
#     for result in thread_results:
#         if result != None or str(result).lower() != "none":
#             append_threadresult.append(result)
#     total_results += append_threadresult.copy()
end_time = datetime.datetime.now()
print(f"[+] Duration Time: {end_time - start_time}")
print(total_results)
if total_results:
    delete_old_data()
    print(f"[+] Total Results: [{len(total_results)}]")

print("[+] Inserting Into DB.")
for result in total_results:
    if not result:
        continue
    # try:
    database_syntax = "Insert Into webapplication_discovery.webapplication_discovery (scannedip, service, response_matcher, statuscode_matcher, createdtime, connection_port) VALUES (%s, %s, %s, %s, %s, %s)"
    result_service = result["service"][:-9]
    response_matcher = result["response_matcher"]
    statuscode_matcher = result["statuscode_matcher"]
    connection_port = result["connection_port"]

    values = [result["scannedip"], result_service, response_matcher, statuscode_matcher, current_time(), connection_port]
    insert_db(database_syntax, values)
    # except Exception as e:
    #     print(f"[-] Failed To Insert into DB. [Err] {e}. [Result] {result}")


