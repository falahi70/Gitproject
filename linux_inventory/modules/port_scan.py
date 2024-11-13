import socket
import sys




def tcp_single_ip_single_port_scan(target, port):
    global port_scan_result
    port = int(port)
    tmp_target = target.copy()
    target_ipaddress = target["ipaddress_string"]
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(2)
        result = tcp.connect_ex((target_ipaddress, port))
        # print(result)
        if result == 0:
            tmp_target["islive"] = True
        else:
            tmp_target["islive"] = False

        return tmp_target.copy()

    except Exception as e:
        print(f"[-] Error on port scan process.\n[Err] {e}")
        return tmp_target.copy()
