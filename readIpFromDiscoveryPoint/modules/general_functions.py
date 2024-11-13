import uuid
import datetime
import ipaddress


def generate_new_GUID():
    uuidFour = uuid.uuid4()
    return uuidFour

def current_time():
    return str(datetime.datetime.now())[:19]

def ip_to_decimal(ipv4):
    return int(ipaddress.ip_address(str(ipv4)))


def create_csv(headers, values, outputname):
    output_handle = open(outputname, "w", encoding="utf-8", errors="ignore")

    header_str = ",".join(headers)
    output_handle.write(f"{header_str}\n")
    for value in values:
        value = [str(a) for a in value]
        value = [a.replace(",", "") for a in value]
        value_data = ",".join(value)
        output_handle.write(f"{value_data}\n")

    output_handle.close()
