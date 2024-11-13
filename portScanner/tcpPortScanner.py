import socket
import psycopg2
import argparse
from modules.coresolution import *
from threading import Thread
import datetime
from multiprocessing.pool import ThreadPool

parser = argparse.ArgumentParser(description="TCP Port Scanner")

parser.add_argument("-i", "--ip",
                    default=False,
                    help='Your target IP Address.')

parser.add_argument("-p", "--port",
                    default=False,
                    help='Your target port.')

parser.add_argument("-s", "--show",
                    default=False,
                    action="store_true",
                    help='Show scan results in stdout.')

options = parser.parse_args()

def print_verbose(message):
    if not options.show:
        print(message)

print_verbose("[+] Opening Config File.")
try:
    config_handle = open(r"appsettings.json", "r", encoding="utf-8", errors="ignore")
    config = json.load(config_handle)
    config_handle.close()
except:
    print("[-] Failed to open appsettings.json")
    sys.exit(0)

output_protocols = {
}



coresolution_handle = coresolution(config["coreInspectScheme"],
                                   config["coreInspectIpAddress"],
                                   config["coreInspectUsername"],
                                   config["coreInspectPassword"])
coresolution_handle.authenticate()

if options.port:
    print_verbose(f"[+] Scanning IPs For [{options.port}] Open Port.")
    output_protocols[options.port] = "port"
else:
    print_verbose("[+] Fetching all protocols.")
    cpl_result = coresolution_handle.execute_cpl(
        '|   search      resourceType = "connectionMethodDiscovery" and status = "Enabled" | fields name, port , description')
    for resource in cpl_result:
        resource_port = resource["port"]
        resource_protocol_name = resource["name"]
        output_protocols[resource_port] = resource_protocol_name


# output_protocols = {9100: 'HP_Printer'}



if not options.ip:
    ip_list = FetchResourceType(username="coreinspectapiuser", password="Abcd123")
    ip_count = len(ip_list)
    thread_num = int(ip_count/4)

else:
    ip_list = options.ip.split(",")
    thread_num = 1

def current_time():
    return str(datetime.datetime.now())[:19]

ips_list = []
def tcp_single_ip_single_port_scan(ip, port):
    port = int(port)
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(10)
        result = tcp.connect_ex((ip, port))
        ip_dict = {}
        ip_dict["ipaddress"] = ip
        ip_dict["openport"] = str(port)
        if result == 0:
            try:
                ip_dict["discoveredconnectionmethod"] = output_protocols[str(port)]
                ip_dict["state"] = "open"
            except:
                ip_dict["discoveredconnectionmethod"] = output_protocols[port]
                ip_dict["state"] = "open"
            ips_list.append(ip_dict.copy())
        else:
            if options.show:
                ip_dict["state"] = "closed"
                ips_list.append(ip_dict.copy())
    except Exception as e:
        print(e)
        return {}

def db_connect():
    conn = psycopg2.connect(
        host=config["databaseHost"],
        database=config["databaseName"],
        user=config["databaseUsername"],
        password=config["databasePassword"])
    cursor = conn.cursor()
    return conn, cursor

def insert_ips_to_database(ips_list):
    conn, cursor = db_connect()
    openports = output_protocols.keys()
    openports = [str(port) for port in openports]
    openports = "','".join(openports)
    openports = f"('{openports}')"
    cursor.execute(f"delete from connection_method_discovery.\"connectionMethod\" where openport IN {openports}")
    conn.commit()
    for ip in ips_list:
        #columns = ["ipaddress", "openport", "discoveredconnectionmethod", "createdtime"]
        values = [ip["ipaddress"], ip["openport"], ip["discoveredconnectionmethod"], str(datetime.datetime.now())[:19]]
        query = "insert into connection_method_discovery.\"connectionMethod\" (ipaddress, openport, discoveredconnectionmethod, createdtime) VALUES (%s,%s,%s,%s)"
        print(query)
        try:
            cursor.execute(query, values)
            conn.commit()
        except Exception as e:
            print(f"[-] Failed to insert in DB.\n[Err] {e}")

#tcp_single_ip_single_port_scan(ip, port)
print_verbose(f"[!] Scanning all IP Addresses [{len(ip_list)}]. ({current_time()})")
pool = ThreadPool(processes=thread_num)
results = []
while (ip_list):
    target_ip = ip_list.pop()
    # if target_ip != "10.10.136.59":
    #     continue
    # print(f"[!] Target IP: {target_ip}")
    for each_port in output_protocols.keys():
        results.append(pool.apply_async(tcp_single_ip_single_port_scan, (target_ip, each_port,), ))
        
pool.close()  # Done adding tasks.
pool.join()  # Wait for all tasks to complete.
# results = [result.get() for result in results]
print_verbose(f"[+] Scan Finished. ({current_time()})")
print_verbose("[+] Inserting Data Into Database.")
if options.show:
    for data in ips_list:
        print(str(json.dumps(data)))
else:
    insert_ips_to_database(ips_list)
