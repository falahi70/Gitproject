from ntc_templates.parse import parse_output
from netmiko import ConnectHandler
import argparse
from modules.databaseConnection import *
import ipaddress
import datetime
import paramiko
import sys
import os

os.environ["NTC_TEMPLATES_DIR"] = f"{os.getcwd()}/templates"

parser = argparse.ArgumentParser(description="Parser Engine")

parser.add_argument("-a", "--address",
                    default=False,
                    required=False,
                    help='Enter your target IP address.')

parser.add_argument("-ho", "--hostname",
                    default=False,
                    help='Enter your target Hostname.')

parser.add_argument("-pl", "--parser-platform",
                    default="cisco_ios",
                    help='Enter your parser platform.')

parser.add_argument("-pc", "--parser-command",
                    default=False,
                    required=False,
                    help='Enter your parser command.')

parser.add_argument("-cmd", "--command",
                    default=False,
                    help='Enter Command To Execute On Server.')

parser.add_argument("-ssh", "--ssh-command",
                    default=False,
                    help='Enter your SSH command.')

parser.add_argument("-tn", "--tablename",
                    default=False,
                    help='Enter your table name.')

parser.add_argument("-sn", "--schemaname",
                    default=False,
                    help='Enter your schema name.')

parser.add_argument("-s", "--scanid",
                    default=1,
                    type=int,
                    help='Enter your result scan ID.')

parser.add_argument("-cn", "--credential-name",
                    default=False,
                    required=False,
                    help='Enter credential name for your IP address.')

parser.add_argument("-p", "--profile",
                    default=False,
                    help='Use a profile in order to regenerate JSON output based on that.')

parser.add_argument("-si", "--stdin-parser",
                    default=False,
                    action="store_true",
                    help='Use this switch if you want to pars data from STDIN.')

parser.add_argument("-st", "--store",
                    default=False,
                    action="store_true",
                    help='Store data into database instead of STDOUT.')

parser.add_argument("-v", "--verbose",
                    default=False,
                    action="store_true",
                    help='Show more verbose messages.')

options = parser.parse_args()

if not options.command and not options.ssh_command and not options.stdin_parser:
    print("[-] Please Enter A Command To Execute On Server.")
    sys.exit(0)

def current_time():
    c_time = str(datetime.datetime.now())
    return c_time[:19]

def verbose_print(message):
    if options.verbose:
        print(message)

def execute_command(ipaddress, username, password, command="show inventory"):
    try:
        device = ConnectHandler(device_type="cisco_ios", ip=ipaddress, username=username, password=password)
        try:
            output = device.send_command(command)
            device.disconnect()
        except Exception as e:
            print("[-] Failed To Execute Command On Specified Device.")
            verbose_print(f"[DBUG] Error: {e}")
            return ""
    except Exception as e:
        print(f"[-] Failed To Execute Command On Device:\n\t{e}")
        sys.exit(0)
    if "Invalid input detected" in output:
        print("[-] Command Is Not Valid.")
        sys.exit(0)
    return output

def execute_ssh_command(ipaddress, username, password, command):
    verbose_print(f"[DBUG] IP Address: {ipaddress}")
    verbose_print(f"[DBUG] command: {command}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ipaddress, username=username, password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
    except Exception as e:
        print(f"[-] Failed To Execute Command On Device:\n\t{e}")
        sys.exit(0)
    output = "".join(ssh_stdout.readlines())
    errors = "".join(ssh_stderr.readlines())
    if len(errors) > 1:
        print("[-] Command Is Not Supported By The Specified Device.")
        verbose_print(f"[DBUG] Error: {errors}")
        sys.exit(0)
    return output

def profile_handler(command_output, profile):
    # print(f"Len command_output: {len(command_output)}")
    profile_output = []
    for output in command_output:
        # print(output)
        new_profile = profile.copy()
        for key, value in new_profile.items():
            value = str(value)
            if len(value.split(" | ")) > 1:  # $dhcpenabled$ | Disabled,False;Enabled,True
                value_data = value.split(" | ")[0]  # $dhcpenabled$
                value_split = value.split(" | ")[-1]  # Disabled,False;Enabled,True
            else:
                value_data = value  # $dhcpenabled$
                value_split = False
            if str(value_data).count("$") == 2:
                join_key = value_data.replace("$", "")  # dhcpenabled
                data = output[join_key]  # dhcpenabled --> Disabled
                # if key == "caption":
                    # print(f"data: {data}")
                    # print(f"join_key: {join_key}")
                    # print(f"value_split: {value_split}")
                if value_split:  # Disabled,False;Enabled,True
                    replace_list = value_split.split(";")  # ["Disabled,False","Enabled,True"]
                    for replace_action in replace_list:  # Disabled,False
                        original, new_data = replace_action.split(",")  # Original: Disabled, new_data: False
                        data = data.replace(original, new_data)
                try:
                    new_profile[key] = data
                except:
                    new_profile[key] = "unknown"
            else:
                new_profile[key] = value
        # print(new_profile)
        profile_output.append(new_profile)
    
    return profile_output

def sanitize_data(parsed_data):
    for data in parsed_data:
        if options.hostname:
            data["hostname"] = options.hostname
        data["scannedip"] = int(ipaddress.ip_address(options.address))
        data["command"] = options.command
        data["parser"] = options.parser_command
        data["createdtime"] = current_time()
        for key, value in data.items():
            try:
                data[key] = value.strip()
            except Exception as e:
                pass
    return parsed_data

if options.store and not options.tablename:
    print("[-] Please specify table name using -tn switch.")
    sys.exit(0)

if options.credential_name:
    verbose_print("[DBUG] Fetching Credential From Database.")
    try:
        username, password = get_credential(options.credential_name)
        verbose_print("[DBUG] Credential Fetched.")
    except Exception as e:
        print(f"[-] Failed To Fetch Username/Password.\n[Err] {e}")
        sys.exit(0)


if options.credential_name:
    if options.ssh_command:
        command_output = execute_ssh_command(options.address, username, password, options.ssh_command)
    else:
        command_output = execute_command(options.address, username, password, options.command)
    verbose_print(f"[DBUG] Command Executed.\n\t{command_output}")

elif options.stdin_parser:
    command_output = sys.stdin.read()

else:
    print("[-] No Output Found To Pars.")
    sys.exit(0)
    
output_handle = open("command_output.txt", "w", encoding="utf-8", errors="ignore")
output_handle.write(command_output)
output_handle.close()

#try:
#print(f"Command: {command_output}")
#print(f"Parser Commad: {options.parser_command}")
#print(f"Parser Platform: {options.parser_platform}")

try:
	parsed_output = parse_output(platform=options.parser_platform, command=options.parser_command, data=command_output)
except Exception as e:
   print(f"[-] Failed To Parse Command Output:\n\t[Err] {e}")
   sys.exit(0)
   
verbose_print(f"[DBUG] Sanitized Output.\n\t{parsed_output}")

if options.profile:
    try:
        profile = json.load(open(rf"cd /CoreInspect/agents/parserengine/profiles/{options.profile}", "r", encoding="utf-8", errors="ignore"))
    except Exception as e:
       print(f"[-] Error while trying to read profile.\n\t[Err] {e}")
       sys.exit(0)

    parsed_output = profile_handler(parsed_output, profile)

parsed_output = sanitize_data(parsed_output)
#print(f"[*] Parsed Output:\n{parsed_output}")
if not options.store:
    vlan_parsed = str(parsed_output)
    vlan_parsed = vlan_parsed.replace('"', r'\"')
    vlan_parsed = vlan_parsed.replace("'", '"')
    vlan_parsed = vlan_parsed.replace(": False", ': false')
    vlan_parsed = vlan_parsed.replace(": True", ': true')
    print(vlan_parsed)

else:
    if len(parsed_output) < 1:
        print('[-] No Data Returned From Parser Engine.')
        sys.exit(0)

    current_schema_name = options.schemaname.lower() if options.schemaname else options.parser_platform.lower()
    schema_list = get_schema_list()
    if current_schema_name not in schema_list:
        verbose_print(f"[DBUG] Schema Does Not Exist. Creating [{current_schema_name}]")
        create_new_schema(current_schema_name)

    current_table_name = options.tablename
    tablename_list = get_tablename_list(current_schema_name)
    if current_table_name not in tablename_list:
        verbose_print(f"[DBUG] Table Does Not Exist. Creating [{current_table_name}]")
        create_new_table(current_schema_name, current_table_name)

    current_column_list = parsed_output[0].keys()
    column_list = get_columnname_list(current_schema_name, current_table_name)
    for column in current_column_list:
        if column not in column_list:
            verbose_print(f"[DBUG] Column Does Not Exist. Creating [{column}]")
            create_new_column(current_schema_name, current_table_name, column)
    scanid = get_scan_id(current_schema_name, current_table_name, options.hostname)
    for data in parsed_output:
        verbose_print("[*] Saving data into database...")
        data["scanid"] = scanid
        insert_dictionary_data(current_schema_name, current_table_name, data)


