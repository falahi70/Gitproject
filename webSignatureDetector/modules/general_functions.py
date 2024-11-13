import json
from .coresolution import *




def load_config(location=False):
    file_handle = open(location, "r", encoding="utf-8", errors="ignore") if location else open("appsettings.json", "r", encoding="utf-8", errors="ignore")
    json_config = json.load(file_handle)
    file_handle.close()
    return json_config

def get_target(target, target_list):
    targets = []
    if target:
        targets.append(target)
    if target_list:
        file_handle = open(target_list, "r", encoding="utf-8", errors="ignore")
        for line in file_handle.readlines():
            line = line.strip()
            targets.append(line)
        file_handle.close()
    return targets

def load_patterns(location=False):
    file_handle = open(location, "r", encoding="utf-8", errors="ignore") if location else open("patterns.json", "r",
                                                                                               encoding="utf-8",
                                                                                               errors="ignore")
    json_patterns = json.load(file_handle)
    file_handle.close()
    return json_patterns