import getpass
from modules.general_functions import *
from modules.database_connections import *
from modules.coresolution import *
import subprocess



config = load_config()

coresolution_handle = coresolution(
    config["coresolution_connection"]["scheme"],
    config["coresolution_connection"]["address"],
    config["coresolution_connection"]["username"],
    config["coresolution_connection"]["password"]
)
coresolution_handle.authenticate()

database_handle = databaseConnection(
    config["database_connection"]["hostname"],
    config["database_connection"]["username"],
    config["database_connection"]["password"],
    config["database_connection"]["db_name"],
)


def get_cisco_target_commands():
    coresoluton_cpl = '|snippet "CiscoModule"'

    target_objects = coresolution_handle.execute_cpl(coresoluton_cpl)
    target_commands = []

    for object in target_objects:
        path = fr"/CoreInspect/agents/parserengine"
        command = object["command"]
        command = command.replace("cd parserengine; ", f"cd {path};")
        target_commands.append(command)

    return target_commands

for command in get_cisco_target_commands():
    process_handle = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process_handle.communicate(timeout=120)
        print(f"[!] Output: {stdout}")
    except Exception as e:
        print(f"[-] Failed to execute command.\n[CMD] {command}\n[Err] {e}")
