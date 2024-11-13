import socket
import psycopg2
from threading import Thread
import datetime
import sys
import concurrent.futures


def current_time():
    return str(datetime.datetime.now())[:19]


def tcp_single_ip_single_port_scan(target_object, port):
    target_ipaddress = target_object["ipaddress_string"]
    port = int(port)
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(2)
        result = tcp.connect_ex((target_ipaddress, port))

        if result == 0:
            target_object["islive"] = True
        else:
            target_object["islive"] = False

        return target_object

    except Exception as e:
        target_object["islive"] = False
        return target_object


def portscan_targets(target_lists, port, thread_count):
    scan_results = []
    while len(target_lists) > 0:
        print(f"[PS] Spawning [{thread_count}] Threads. Left: [{len(target_lists)}] ({current_time()})")
        thread_queue = target_lists[:thread_count]
        del target_lists[:thread_count]

        executor = concurrent.futures.ThreadPoolExecutor()
        thread_pool = []

        for target in thread_queue:
            thread_pool.append(executor.submit(tcp_single_ip_single_port_scan, target, port))

        returned_data = [f.result() for f in thread_pool]
        scan_results += returned_data

    return scan_results
