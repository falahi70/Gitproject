import datetime
import json
import requests
import sys
import subprocess
import ipaddress
import uuid
import os
import tldextract

class ParseURL:
    def __init__(self, input_url):
        self.input_url = input_url
        self.extracted_data = tldextract.extract(self.input_url)

        if "https://" in input_url[:15]:
            self.scheme = "https://"
        elif "http://" in input_url[:15]:
            self.scheme = "http://"
        else:
            self.scheme = None

        self.sld = self.extracted_data[1]
        self.tld = self.extracted_data[2]
        self.subdomain = self.extracted_data[0]

        self.domain = f"{self.sld}.{self.tld}"
        self.hostname = self.domain if not self.subdomain else f"{self.subdomain}.{self.domain}"
        self.url = f"{self.scheme}{self.hostname}"
        # self.url = f"{self.scheme}{self.subdomain}{self.sld}.{self.tld}"
        self.subdomainsld = f"{self.subdomain}{self.sld}" if not self.subdomain else f"{self.subdomain}.{self.sld}"

def current_time(get="filename"):
    c_time = str(datetime.datetime.now())[:19]
    if get == "filename":
        c_time = c_time.replace(" ", "")
        c_time = c_time.replace(":", "")
        c_time = c_time.replace("-", "")
    return c_time

def return_file_lines(filename):
    return_data = []
    with open(filename, "r", encoding="utf-8", errors="ignore") as filedata:
        file_lines = filedata.readlines()
        for line in file_lines:
            line = line.strip()
            return_data.append(line)
    return return_data

def current_time_filename():
    ctime = str(datetime.datetime.now())
    ctime = ctime[:19]
    ctime = ctime.replace(" ","")
    ctime = ctime.replace("-","")
    ctime = ctime.replace(":","")
    return ctime

def decode_stdout(input):
    output = input.decode("utf-8")
    output = output.replace("\r\n", "")
    output = output.replace("\n", "")
    return output

def fetch_dns_resolver():
    url = 'https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt'
    output_name = "resolvers.txt"
    resolvers = requests.get(url, allow_redirects=True)
    file_hanle = open(output_name, "w", encoding="utf-8")
    file_hanle.write(resolvers.text)
    file_hanle.close()
    return output_name

current_verbose_status = False
def print_message(message=None, symbol="+", verbose=False):
    if not verbose:
        print(f"[{symbol}] [{current_time(get='full')}] {message}")
    else:
        if current_verbose_status:
            print(f"[#] [{current_time(get='full')}] {message}")

def delete_file(filename):
    try:
        os.chmod(filename, 0o777)
        os.remove(filename)
    except Exception as e:
        print_message(f"Failed To Delete [{filename}]. [Err] {e}", verbose=True)

def load_config():
    try:
        file_handle = open("appsettings.json", "r", encoding="utf-8", errors="ignore")
        config_json = json.load(file_handle)
        file_handle.close()
        return config_json
    except Exception as e:
        print(f"[-] Failed to open configuration file.\n[Err] {e}")
        sys.exit(-1)

class ParseURL:
    def __init__(self, input_url):
        self.input_url = input_url
        self.extracted_data = tldextract.extract(self.input_url)

        if "https://" in input_url[:15]:
            self.scheme = "https://"
        elif "http://" in input_url[:15]:
            self.scheme = "http://"
        else:
            self.scheme = None

        self.sld = self.extracted_data[1]
        self.tld = self.extracted_data[2]
        self.subdomain = self.extracted_data[0]

        self.domain = f"{self.sld}.{self.tld}"
        self.hostname = self.domain if not self.subdomain else f"{self.subdomain}.{self.domain}"
        self.url = f"{self.scheme}{self.hostname}"
        # self.url = f"{self.scheme}{self.subdomain}{self.sld}.{self.tld}"
        self.subdomainsld = f"{self.subdomain}{self.sld}" if not self.subdomain else f"{self.subdomain}.{self.sld}"

def domain_access(domain, action="block"):
    parsed_domain = ParseURL(domain)
    def block_domain(domain):
        domain = parsed_domain.hostname

        print_message(f"Backup old [/etc/hosts]", "*", verbose=True)
        command = "cp /etc/hosts /etc/hosts.bak"
        stdout, stderr = execute_command(command)

        print_message(f"Adding [{domain}] To [/etc/hosts]", "*", verbose=True)
        file_handle = open("/etc/hosts", "a+", encoding="utf-8", errors="ignore")
        file_handle.write(f"\n127.0.0.0 {domain}\n")
        file_handle.close()

    def unblock_domain():
        print_message(f"Restoring original [/etc/hosts]", "*", verbose=True)
        command = "cp /etc/hosts.bak /etc/hosts"
        stdout, stderr = execute_command(command)

    if action.lower() == "block":
        block_domain(domain)
    else:
        unblock_domain()

def check_stderr(std_err):
    keyword_filters = [
        "Encountered an error while executing autocalibration"
    ]
    std_err = str(std_err.decode('utf-8'))
    if len(std_err) > 3:
        hit_error = True
        for error_message in keyword_filters:
            if error_message in std_err:
                hit_error = False
        if hit_error:
            print_message(f"Error On Executing Command.\n[Err] {std_err}", "-")
            sys.exit(0)

def execute_command(command):
    command_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = command_result.communicate()
    check_stderr(std_err)
    return std_out, std_err

def action_files(filenames, outputname, action="merge", remove=False):
    filename_string = " ".join(filenames)
    if action.lower() == "merge":
        command = f'cat {filename_string} | sort -u > {outputname}'
    elif action.lower() == "dedup":
        command = f'cat {filename_string} | uro > {outputname}'
    else:
        print_message(f"No Valid Action Found For Files [{action}].", "-")
        return -1

    stdout, stderr = execute_command(command)

    if remove:
        for filename in filenames:
            delete_file(filename)

    return outputname

def check_content_length(filename):
    os.chmod(filename, 0o777)
    command = f'head -n 1 {filename}'
    command_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = command_result.communicate()
    std_out = str(std_out.decode("utf-8"))
    if int(len(std_out)) < 3:
        return False
    return True

def parse_ffuf_output(ffuf_output, parsed_output_filename):
    def check_ffuf_output(outputname):
        command = f'cat {outputname} | jq -r \'."results"[]."url"\' | head -n 1'
        # print(command)
        command_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        std_out, std_err = command_result.communicate()
        std_out = str(std_out.decode("utf-8"))
        if int(len(std_out)) < 3:
            return False
        return True

    print_message("Checking if FFUF Has Results.", "*", verbose=True)
    if check_ffuf_output(ffuf_output):
        json_pars_command = f'cat {ffuf_output} | jq -r \'."results"[]."url"\' | sort -u > {parsed_output_filename}'
        # print(json_pars_command)
        std_out, std_err = execute_command(json_pars_command)

        try:
            os.chmod(parsed_output_filename, 0o777)
            delete_file(ffuf_output)
        except Exception as e:
            print("[-] Failed To Cleanup FFUF Output.")

        return parsed_output_filename

    else:
        delete_file(ffuf_output)
        print_message("FFUF Had No Results.", "-", verbose=True)
        return False

def ip2long(str_ipaddress):
    return int(ipaddress.ip_address(str_ipaddress))

def long2ip(int_ipaddress):
    return str(ipaddress.ip_address(int(int_ipaddress)))

def generate_new_GUID():
    uuidFour = str(uuid.uuid4())
    uuidFour = uuidFour.replace("{", "").replace("}", "")
    return uuidFour
