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
        tmp_model = {
            "id": value[0],
            "discoverynodeip": value[2],
            "mac": value[4],
            "ip": value[5],
            "createdtime": value[3],
            "discoverytype": value[6],
            "scanid": value[1]
        }
        tmp_string = ""
        for column in headers:
            data = tmp_model.get(column, "")
            data = str(data).strip()
            tmp_string += f"{data},"
        tmp_string = tmp_string[:-1]
        #value = [str(a) for a in value]
        #value = [a.replace(",", "") for a in value]
        #value_data = ",".join(value)
        output_handle.write(f"{tmp_string}\n")

    output_handle.close()
