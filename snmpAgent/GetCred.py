import subprocess
import argparse
import psycopg2
import sys
import datetime
import json
import getpass
from modules.databaseConnection import *
import time
from modules.coresolution import *

def fetch_credential(credential_name):
    #verbose_print(f"[+] Fetching Credential From CoreSolution.")

    if int(options.version) == 3:
        credential_handle = coresolution_handle.get_snmp_credential(credential_name)
    else:
        credential_handle = coresolution_handle.get_credential(credential_name)


    if int(options.version) == 3:
        credential = {
            "username": credential_handle["username"],
            "authentication_phrase": credential_handle["authentication_phrase"],
            "authentication_type": credential_handle["authentication_type"],
            "encryption_phrase": credential_handle["encryption_phrase"],
            "encryption_type": credential_handle["encryption_type"],
        }
    else:
        credential = {
            "community": credential_handle["password"]
        }
    return credential
print(fetch_credential('SNMP-V3'))