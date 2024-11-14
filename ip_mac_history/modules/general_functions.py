import uuid
import datetime
import ipaddress


def generate_new_GUID():
    uuidFour = str(uuid.uuid4())
    uuidFour = uuidFour.replace("}", "").replace("{", "")
    return uuidFour

def current_time():
    return str(datetime.datetime.now())[:19]

def ip_to_decimal(ipv4):
    return int(ipaddress.ip_address(str(ipv4)))


def create_csv(headers, values, outputname):
    output_handle = open(outputname, "w", encoding="utf-8", errors="ignore")

    header_str = ",".join(headers)
    output_handle.write(f"{header_str}\n")

    for data in values:
        tmp_string = ""
        for column in headers:
            write_data = str(data.get(column, "N/A"))
            # write_data = write_data.replace(",", "")
            # write_data = write_data.replace('"', '""')
            tmp_string += f"{write_data};"
        tmp_string = tmp_string[:-1]
        output_handle.write(f"{tmp_string}\n")

    output_handle.close()
